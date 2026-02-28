def process_zip_background(user_id, parent_doc_id, filepath, file_hash, filename, doc_category, app_context):
    """
    Background job to process a zip file progressively.
    Stages:
      uploaded -> extracting -> extracted -> generating_previews -> parsing -> pending_approval
    """
    with app_context:
        import time
        import os
        start_time = time.time()
        zip_errors = []
        transactions = []
        account_info = {}
        child_doc_map = {}
        target_doc_ids = []
        transactions_with_hashes = []
        skipped_duplicate_files = 0
        from database import update_document_status, add_document, get_duplicate_document, add_transactions_bulk, get_or_create_account, get_db
        from categorizer import categorize_transactions_bulk
        from parsers import parse_document, compute_transaction_hash, ALLOWED_EXTENSIONS
        import zipfile
        import shutil
        import hashlib
        from flask import current_app

        logger = logging.getLogger('forensic_cpa_ai')

        # Update status to extracting
        update_document_status(user_id, parent_doc_id, status='extracting')

        extracted_dir = filepath + "_extracted"
        os.makedirs(extracted_dir, exist_ok=True)
        
        # Zip bomb & slip limits
        MAX_FILES = 500
        MAX_ARCHIVE_SIZE = 200 * 1024 * 1024  # 200 MB
        MAX_FILE_SIZE = 50 * 1024 * 1024      # 50 MB
        
        extracted_paths = []
        
        extract_start = time.time()
        try:
            with zipfile.ZipFile(filepath, 'r') as zip_ref:
                total_size = 0
                file_count = 0
                
                for zinfo in zip_ref.infolist():
                    if zinfo.is_dir(): continue
                    if '..' in zinfo.filename or zinfo.filename.startswith('/') or zinfo.filename.startswith('\\'): continue
                    basename = os.path.basename(zinfo.filename)
                    if basename.startswith('._') or '__MACOSX' in zinfo.filename: continue
                    ext = basename.rsplit('.', 1)[1].lower() if '.' in basename else ''
                    if (ext not in ALLOWED_EXTENSIONS and ext != 'zip') or basename.lower().endswith('.zip'): continue
                        
                    file_count += 1
                    if file_count > MAX_FILES:
                        raise Exception("Zip file contains too many entries (exceeds 500 max).")
                        
                    # Hash the file in-memory
                    file_hash_obj = hashlib.sha256()
                    file_size = 0
                    
                    safe_path = os.path.abspath(os.path.join(extracted_dir, basename))
                    if not safe_path.startswith(os.path.abspath(extracted_dir)): continue

                    with open(safe_path, 'wb') as f_out:
                        with zip_ref.open(zinfo) as f_in:
                            while chunk := f_in.read(8192):
                                file_hash_obj.update(chunk)
                                file_size += len(chunk)
                                total_size += len(chunk)
                                if file_size > MAX_FILE_SIZE:
                                    raise Exception(f"File {zinfo.filename} exceeds 50MB size limit.")
                                if total_size > MAX_ARCHIVE_SIZE:
                                    raise Exception("Zip bomb detected: exceeded 200MB uncompressed limit.")
                                f_out.write(chunk)
                                
                    child_hash = file_hash_obj.hexdigest()
                    
                    # Check duplicate
                    dup_id = get_duplicate_document(user_id, child_hash)
                    if dup_id:
                        logger.info(f"Skipping duplicate zip child: {basename}")
                        skipped_duplicate_files += 1
                        os.remove(safe_path)
                        continue
                        
                    extracted_paths.append((safe_path, child_hash, basename))
                    
                    # Create child document record
                    c_ext = basename.rsplit('.', 1)[1].lower() if '.' in basename else 'pdf'
                    c_id = add_document(
                        user_id=user_id,
                        filename=basename,
                        original_path=None,
                        file_type=c_ext,
                        doc_category=doc_category,
                        account_id=None,
                        content_sha256=child_hash,
                        parent_document_id=parent_doc_id,
                        status='extracted'
                    )
                    child_doc_map[child_hash] = c_id

            extract_time = time.time() - extract_start
            logger.info(f"Background ZIP extracted in {extract_time:.2f}s")
            
            update_document_status(user_id, parent_doc_id, status='generating_previews')
            for child_hash, c_id in child_doc_map.items():
                update_document_status(user_id, c_id, status='generating_previews')
            
            update_document_status(user_id, parent_doc_id, status='parsing')
            for child_hash, c_id in child_doc_map.items():
                update_document_status(user_id, c_id, status='parsing')
                
            parse_start = time.time()
            
            # Parallel processing of extracted files
            def parse_task(args):
                f_path, c_hash, b_name = args
                t, ai = parse_document(f_path, 'auto')
                return c_hash, b_name, t, ai

            from concurrent.futures import ThreadPoolExecutor, as_completed
            # Use bounded pool
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_to_file = {executor.submit(parse_task, item): item for item in extracted_paths}
                for future in as_completed(future_to_file):
                    try:
                        c_hash, b_name, t, ai = future.result()
                        if t:
                            for trans in t:
                                trans['_source_file'] = b_name
                                trans['_source_hash'] = c_hash
                            transactions.extend(t)
                        if not account_info and ai:
                            account_info = ai
                    except Exception as inner_e:
                        zip_errors.append(f"{future_to_file[future][2]}: {inner_e}")
                        logger.warning(f"Failed to parse inner zip file: {inner_e}")

            if zip_errors and not transactions:
                raise Exception(f"Failed to process zip archive: {'; '.join(zip_errors)}")

            if not account_info:
                account_info = {'institution': 'Multiple Documents', 'account_type': 'bank', 'account_number': 'Zip Archive'}
                
            # Database saving phase
            if account_info.get('account_number'):
                account_id = get_or_create_account(
                    user_id=user_id,
                    account_name=account_info.get('account_name', account_info.get('institution', 'Unknown')),
                    account_number=account_info['account_number'],
                    account_type=account_info.get('account_type', 'bank'),
                    institution=account_info.get('institution', 'Unknown'),
                    cardholder_name=account_info.get('account_name'),
                    card_last_four=account_info.get('account_number', '')[-4:] if account_info.get('account_number') else None
                )
                conn = get_db()
                try:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE documents SET account_id = ?, statement_start_date = ?, statement_end_date = ? WHERE id = ?",
                                   (account_id, account_info.get('statement_start'), account_info.get('statement_end'), parent_doc_id))
                    for c_id in child_doc_map.values():
                        cursor.execute("UPDATE documents SET account_id = ? WHERE id = ?", (account_id, c_id))
                    conn.commit()
                finally:
                    conn.close()
            else:
                account_id = None
                
            global_cardholder = account_info.get('account_name', '')
            global_last_four = str(account_info.get('account_number', ''))[-4:] if account_info.get('account_number') else ''

            for trans in transactions:
                if not trans.get('cardholder_name'):
                    trans['cardholder_name'] = global_cardholder
                if not trans.get('card_last_four'):
                    trans['card_last_four'] = global_last_four

            categorized_results = categorize_transactions_bulk(user_id, transactions, account_id)
            for i, trans in enumerate(transactions):
                cat_result = categorized_results[i]
                trans['category'] = cat_result['category']
                trans['subcategory'] = cat_result['subcategory']
                trans['is_personal'] = cat_result['is_personal']
                trans['is_business'] = cat_result['is_business']
                trans['is_transfer'] = cat_result['is_transfer']
                trans['is_flagged'] = cat_result['is_flagged']
                trans['flag_reason'] = cat_result['flag_reason']
                trans['payment_method'] = cat_result.get('payment_method', trans.get('payment_method', ''))

            doc_stats = {}
            for child_hash, c_id in child_doc_map.items():
                doc_stats[c_id] = {'added': 0, 'skipped': 0, 'total': 0}
                
            for trans in transactions:
                target_doc_id = parent_doc_id
                child_hash = trans.get('_source_hash')
                if child_hash and child_hash in child_doc_map:
                    target_doc_id = child_doc_map[child_hash]

                txn_fingerprint = compute_transaction_hash(
                    account_scope_id=account_id,
                    trans_date=trans['trans_date'],
                    amount=trans['amount'],
                    description=trans['description'],
                    post_date=trans.get('post_date', trans.get('trans_date')),
                    check_number=trans.get('check_number')
                )

                transactions_with_hashes.append({
                    'trans': trans,
                    'txn_fingerprint': txn_fingerprint
                })
                target_doc_ids.append(target_doc_id)

            added, skipped, trans_doc_stats = add_transactions_bulk(
                user_id=user_id,
                account_id=account_id,
                transactions_with_hashes=transactions_with_hashes,
                target_doc_ids=target_doc_ids
            )
            
            for d_id, stats in trans_doc_stats.items():
                if d_id not in doc_stats:
                    doc_stats[d_id] = {'added': 0, 'skipped': 0, 'total': 0}
                doc_stats[d_id]['added'] += stats['added']
                doc_stats[d_id]['skipped'] += stats['skipped']
                doc_stats[d_id]['total'] += stats['total']

            for d_id, stats in doc_stats.items():
                update_document_status(
                    user_id, 
                    d_id, 
                    status='pending_approval', 
                    parsed_count=stats['total'], 
                    import_count=stats['added'], 
                    skipped_count=stats['skipped']
                )
                
            if parent_doc_id not in doc_stats:
                update_document_status(
                    user_id, 
                    parent_doc_id, 
                    status='pending_approval', 
                    parsed_count=0, 
                    import_count=0, 
                    skipped_count=0
                )
                
            parse_time = time.time() - parse_start
            total_time = time.time() - start_time
            logger.info(f"Background ZIP parsed/imported in {parse_time:.2f}s. Total Job time {total_time:.2f}s.")

        except Exception as e:
            logger.error(f"Background ZIP task failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            update_document_status(user_id, parent_doc_id, status='failed', failure_reason=str(e)[:250])
            for child_hash, c_id in child_doc_map.items():
                update_document_status(user_id, c_id, status='failed', failure_reason="Parent ZIP processing failed")
        finally:
            shutil.rmtree(extracted_dir, ignore_errors=True)
