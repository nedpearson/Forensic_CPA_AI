"""
PDF Forensic Report Generator for Forensic CPA AI.
Generates a formatted PDF report with executive summary, findings,
key transactions, and analysis data.
"""
import os
import io
from datetime import datetime
from fpdf import FPDF
from database import get_db, build_filter_clause
from categorizer import get_executive_summary, get_money_flow, get_recurring_transactions


class ForensicReport(FPDF):
    """Custom PDF class for forensic reports."""

    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font('Helvetica', 'B', 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 6, 'FORENSIC CPA AI - Confidential Report', align='L')
        self.cell(0, 6, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', align='R', new_x='LMARGIN', new_y='NEXT')
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(3)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', align='C')

    def section_title(self, title, icon=''):
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(30, 30, 30)
        self.ln(4)
        self.cell(0, 10, f'{icon}  {title}', new_x='LMARGIN', new_y='NEXT')
        self.set_draw_color(59, 130, 246)
        self.set_line_width(0.8)
        self.line(10, self.get_y(), 80, self.get_y())
        self.set_line_width(0.2)
        self.ln(4)

    def sub_title(self, title):
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(60, 60, 60)
        self.cell(0, 8, title, new_x='LMARGIN', new_y='NEXT')
        self.ln(1)

    def body_text(self, text):
        self.set_font('Helvetica', '', 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def stat_box(self, label, value, x, y, w=42, severity='info'):
        colors = {
            'danger': (248, 81, 73),
            'warning': (210, 153, 34),
            'success': (63, 185, 80),
            'info': (88, 166, 255),
        }
        r, g, b = colors.get(severity, colors['info'])
        self.set_fill_color(r, g, b)
        self.set_xy(x, y)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(255, 255, 255)
        self.cell(w, 12, str(value), align='C', fill=True)
        self.set_xy(x, y + 12)
        self.set_font('Helvetica', '', 7)
        self.set_text_color(r, g, b)
        self.cell(w, 5, label, align='C')

    def data_table(self, headers, rows, col_widths=None, max_rows=50):
        if not col_widths:
            total = 190
            col_widths = [total / len(headers)] * len(headers)

        # Header
        self.set_font('Helvetica', 'B', 8)
        self.set_fill_color(40, 40, 50)
        self.set_text_color(255, 255, 255)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 7, str(h), border=1, fill=True, align='C')
        self.ln()

        # Rows
        self.set_font('Helvetica', '', 8)
        self.set_text_color(40, 40, 40)
        for row_idx, row in enumerate(rows[:max_rows]):
            if self.get_y() > 265:
                self.add_page()
                # Re-draw header
                self.set_font('Helvetica', 'B', 8)
                self.set_fill_color(40, 40, 50)
                self.set_text_color(255, 255, 255)
                for i, h in enumerate(headers):
                    self.cell(col_widths[i], 7, str(h), border=1, fill=True, align='C')
                self.ln()
                self.set_font('Helvetica', '', 8)
                self.set_text_color(40, 40, 40)

            if row_idx % 2 == 0:
                self.set_fill_color(245, 245, 250)
            else:
                self.set_fill_color(255, 255, 255)

            for i, val in enumerate(row):
                text = str(val)[:40]
                align = 'R' if i > 0 and isinstance(val, (int, float)) else 'L'
                self.cell(col_widths[i], 6, text, border=1, fill=True, align=align)
            self.ln()

        if len(rows) > max_rows:
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(150, 150, 150)
            self.cell(0, 6, f'... and {len(rows) - max_rows} more rows', new_x='LMARGIN', new_y='NEXT')


def generate_forensic_report(user_id, filters=None):
    """Generate the full forensic PDF report and return the file path."""
    pdf = ForensicReport()
    pdf.alias_nb_pages()

    conn = get_db()
    cursor = conn.cursor()
    where, params = build_filter_clause(user_id, filters)

    # ===== PAGE 1: COVER PAGE =====
    pdf.add_page()
    pdf.ln(30)
    pdf.set_font('Helvetica', 'B', 28)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 15, 'FORENSIC FINANCIAL', align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 15, 'ANALYSIS REPORT', align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(5)
    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(1.5)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.set_line_width(0.2)
    pdf.ln(10)

    pdf.set_font('Helvetica', '', 12)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 8, 'Gulf Coast Recovery of Baton Rouge, LLC', align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 8, 'Bank of St. Francisville', align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(5)

    # Get date range
    cursor.execute(f"SELECT MIN(trans_date) as first_date, MAX(trans_date) as last_date, COUNT(*) as cnt FROM transactions {where}", params)
    date_info = dict(cursor.fetchone())
    pdf.set_font('Helvetica', '', 11)
    pdf.cell(0, 8, f'Period: {date_info["first_date"] or "N/A"} to {date_info["last_date"] or "N/A"}', align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 8, f'{date_info["cnt"]} Transactions Analyzed', align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.ln(10)

    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(150, 150, 150)
    pdf.cell(0, 8, f'Report Generated: {datetime.now().strftime("%B %d, %Y at %I:%M %p")}', align='C', new_x='LMARGIN', new_y='NEXT')
    pdf.cell(0, 8, 'CONFIDENTIAL - FOR AUTHORIZED USE ONLY', align='C', new_x='LMARGIN', new_y='NEXT')

    # ===== PAGE 2: EXECUTIVE SUMMARY =====
    pdf.add_page()
    pdf.section_title('EXECUTIVE SUMMARY')

    summary = get_executive_summary(user_id, filters)

    # Risk Score
    risk = summary.get('risk_score', 0)
    risk_label = 'HIGH RISK' if risk >= 60 else 'MEDIUM RISK' if risk >= 30 else 'LOW RISK'
    risk_sev = 'danger' if risk >= 60 else 'warning' if risk >= 30 else 'success'
    pdf.sub_title(f'Overall Risk Assessment: {risk_label} ({risk}/100)')
    pdf.body_text(f'Analysis covers {summary.get("total_analyzed", 0)} transactions from {summary.get("date_range", "N/A")}.')

    # Summary stats
    cursor.execute(f"""
        SELECT
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as deposits,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as withdrawals,
            COALESCE(SUM(CASE WHEN is_transfer = 1 AND amount < 0 THEN ABS(amount) ELSE 0 END), 0) as transfers,
            COALESCE(SUM(CASE WHEN is_personal = 1 THEN ABS(amount) ELSE 0 END), 0) as personal,
            COUNT(CASE WHEN is_flagged = 1 THEN 1 END) as flagged_count
        FROM transactions
        {where}
    """, params)
    stats = dict(cursor.fetchone())

    y = pdf.get_y() + 2
    pdf.stat_box('Total Deposits', f'${stats["deposits"]:,.0f}', 10, y, 36, 'success')
    pdf.stat_box('Total Withdrawals', f'${stats["withdrawals"]:,.0f}', 48, y, 36, 'danger')
    pdf.stat_box('Transfers Out', f'${stats["transfers"]:,.0f}', 86, y, 36, 'warning')
    pdf.stat_box('Personal Spending', f'${stats["personal"]:,.0f}', 124, y, 36, 'warning')
    pdf.stat_box('Flagged', str(stats['flagged_count']), 162, y, 36, 'danger' if stats['flagged_count'] > 0 else 'info')
    pdf.set_y(y + 22)
    pdf.ln(5)

    # Findings
    pdf.sub_title('Key Findings')
    for f in summary.get('findings', []):
        sev = f.get('severity', 'info')
        marker = '[!]' if sev == 'danger' else '[*]' if sev == 'warning' else '[i]'
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(
            248 if sev == 'danger' else 210 if sev == 'warning' else 88,
            81 if sev == 'danger' else 153 if sev == 'warning' else 166,
            73 if sev == 'danger' else 34 if sev == 'warning' else 255
        )
        pdf.cell(8, 6, marker)
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(40, 40, 40)
        pdf.cell(0, 6, f['title'], new_x='LMARGIN', new_y='NEXT')
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(80, 80, 80)
        pdf.cell(15)
        pdf.cell(0, 5, f['detail'], new_x='LMARGIN', new_y='NEXT')
        pdf.ln(2)

    # ===== PAGE 3: FLAGGED TRANSACTIONS =====
    cursor.execute(f"""
        SELECT trans_date, description, amount, cardholder_name, category, flag_reason
        FROM transactions {where} AND is_flagged = 1
        ORDER BY ABS(amount) DESC
    """, params)
    flagged = [dict(r) for r in cursor.fetchall()]

    if flagged:
        pdf.add_page()
        pdf.section_title('FLAGGED TRANSACTIONS')
        pdf.body_text(f'{len(flagged)} transactions have been flagged for review. These include suspicious activity, unusual patterns, and items requiring further investigation.')

        rows = []
        for f in flagged:
            rows.append([
                f['trans_date'] or '',
                (f['description'] or '')[:35],
                f'${abs(f["amount"]):,.2f}',
                f['cardholder_name'] or '',
                (f['flag_reason'] or '')[:30],
            ])
        pdf.data_table(
            ['Date', 'Description', 'Amount', 'Cardholder', 'Reason'],
            rows,
            [22, 60, 25, 35, 48]
        )

    # ===== PAGE 4: PERSONAL SPENDING =====
    cursor.execute(f"""
        SELECT trans_date, description, amount, cardholder_name, category
        FROM transactions {where} AND is_personal = 1
        ORDER BY ABS(amount) DESC
    """, params)
    personal = [dict(r) for r in cursor.fetchall()]

    if personal:
        pdf.add_page()
        pdf.section_title('PERSONAL SPENDING ON BUSINESS ACCOUNTS')
        total_personal = sum(abs(p['amount']) for p in personal)
        pdf.body_text(f'{len(personal)} transactions totaling ${total_personal:,.2f} were classified as personal spending on business accounts.')

        rows = []
        for p in personal:
            rows.append([
                p['trans_date'] or '',
                (p['description'] or '')[:40],
                f'${abs(p["amount"]):,.2f}',
                p['cardholder_name'] or '',
                p['category'] or '',
            ])
        pdf.data_table(
            ['Date', 'Description', 'Amount', 'Cardholder', 'Category'],
            rows,
            [22, 65, 25, 35, 43]
        )

    # ===== PAGE 5: CARDHOLDER COMPARISON =====
    cursor.execute(f"""
        SELECT cardholder_name,
            COUNT(*) as cnt,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as spent,
            COALESCE(SUM(CASE WHEN is_personal = 1 THEN ABS(amount) ELSE 0 END), 0) as personal,
            COALESCE(SUM(CASE WHEN is_transfer = 1 AND amount < 0 THEN ABS(amount) ELSE 0 END), 0) as transfers,
            COUNT(CASE WHEN is_flagged = 1 THEN 1 END) as flagged
        FROM transactions
        {where} AND cardholder_name IS NOT NULL AND cardholder_name != ''
        GROUP BY cardholder_name
        ORDER BY spent DESC
    """, params)
    cardholders = [dict(r) for r in cursor.fetchall()]

    if cardholders:
        pdf.add_page()
        pdf.section_title('CARDHOLDER COMPARISON')
        pdf.body_text('Side-by-side comparison of spending by cardholder, including personal use and flagged transactions.')

        rows = []
        for ch in cardholders:
            rows.append([
                ch['cardholder_name'],
                str(ch['cnt']),
                f'${ch["spent"]:,.2f}',
                f'${ch["personal"]:,.2f}',
                f'${ch["transfers"]:,.2f}',
                str(ch['flagged']),
            ])
        pdf.data_table(
            ['Cardholder', 'Transactions', 'Total Spent', 'Personal', 'Transfers', 'Flagged'],
            rows,
            [40, 25, 30, 30, 30, 20]
        )

    # ===== PAGE 6: MONEY FLOW =====
    flow = get_money_flow(user_id, filters)
    if flow['accounts'] or flow['flows']:
        pdf.add_page()
        pdf.section_title('MONEY FLOW ANALYSIS')

        if flow['accounts']:
            pdf.sub_title('Account Flow Summary')
            rows = []
            for a in flow['accounts']:
                net = a['inflow'] - a['outflow']
                rows.append([
                    a['account_name'] or 'Unknown',
                    a['account_type'] or '',
                    f'${a["inflow"]:,.2f}',
                    f'${a["outflow"]:,.2f}',
                    f'${abs(net):,.2f}',
                ])
            pdf.data_table(
                ['Account', 'Type', 'Inflow', 'Outflow', 'Net'],
                rows,
                [55, 25, 35, 35, 35]
            )
            pdf.ln(5)

        if flow['flows']:
            pdf.sub_title('Cross-Account Transfer Destinations')
            rows = []
            for f in flow['flows']:
                rows.append([
                    f['destination'],
                    f'${f["total"]:,.2f}',
                    str(f['count']),
                    f.get('first_date', ''),
                    f.get('last_date', ''),
                ])
            pdf.data_table(
                ['Destination', 'Total', 'Count', 'First', 'Last'],
                rows,
                [50, 35, 20, 40, 40]
            )

    # ===== PAGE 7: RECURRING TRANSACTIONS =====
    recurring = get_recurring_transactions(user_id, filters)
    if recurring:
        pdf.add_page()
        pdf.section_title('RECURRING TRANSACTIONS')
        pdf.body_text(f'{len(recurring)} recurring payment patterns detected. Regular payments may indicate subscriptions, recurring charges, or potentially unauthorized automatic payments.')

        rows = []
        for r in recurring:
            rows.append([
                (r['description'] or '')[:35],
                r['frequency'],
                str(r['count']),
                f'${r["avg_amount"]:,.2f}',
                f'${r["total_amount"]:,.2f}',
                r['first_date'],
            ])
        pdf.data_table(
            ['Description', 'Frequency', 'Count', 'Avg Amt', 'Total', 'Since'],
            rows,
            [55, 25, 15, 25, 30, 25]
        )

    # ===== PAGE 8: TOP TRANSACTIONS =====
    cursor.execute(f"""
        SELECT trans_date, description, amount, cardholder_name, category, is_flagged
        FROM transactions
        {where}
        ORDER BY ABS(amount) DESC
        LIMIT 50
    """, params)
    top_trans = [dict(r) for r in cursor.fetchall()]

    if top_trans:
        pdf.add_page()
        pdf.section_title('LARGEST TRANSACTIONS')
        pdf.body_text('Top 50 transactions by absolute dollar amount.')

        rows = []
        for t in top_trans:
            flag = '*' if t['is_flagged'] else ''
            rows.append([
                t['trans_date'] or '',
                (t['description'] or '')[:35],
                f'${t["amount"]:,.2f}',
                t['cardholder_name'] or '',
                t['category'] or '',
                flag,
            ])
        pdf.data_table(
            ['Date', 'Description', 'Amount', 'Cardholder', 'Category', 'F'],
            rows,
            [22, 55, 28, 35, 35, 10]
        )

    # ===== PAGE 9: CATEGORY BREAKDOWN =====
    cursor.execute(f"""
        SELECT category,
            COUNT(*) as cnt,
            COALESCE(SUM(CASE WHEN amount < 0 THEN ABS(amount) ELSE 0 END), 0) as spent,
            COALESCE(SUM(CASE WHEN amount > 0 THEN amount ELSE 0 END), 0) as received
        FROM transactions
        {where}
        GROUP BY category
        ORDER BY spent DESC
    """, params)
    categories = [dict(r) for r in cursor.fetchall()]

    if categories:
        pdf.add_page()
        pdf.section_title('SPENDING BY CATEGORY')
        rows = []
        for c in categories:
            rows.append([
                c['category'],
                str(c['cnt']),
                f'${c["spent"]:,.2f}',
                f'${c["received"]:,.2f}',
            ])
        pdf.data_table(
            ['Category', 'Count', 'Spent', 'Received'],
            rows,
            [60, 25, 50, 50]
        )

    # ===== CASE NOTES =====
    cursor.execute("SELECT * FROM case_notes WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    notes = [dict(r) for r in cursor.fetchall()]

    if notes:
        pdf.add_page()
        pdf.section_title('INVESTIGATION NOTES')
        for n in notes:
            sev = n.get('severity', 'info')
            marker = '[!]' if sev == 'danger' else '[*]' if sev == 'warning' else '[i]'
            pdf.set_font('Helvetica', 'B', 10)
            pdf.set_text_color(40, 40, 40)
            pdf.cell(0, 6, f'{marker} {n["title"]} ({n.get("note_type", "general")})', new_x='LMARGIN', new_y='NEXT')
            pdf.set_font('Helvetica', '', 9)
            pdf.set_text_color(60, 60, 60)
            pdf.multi_cell(0, 5, n['content'])
            pdf.set_font('Helvetica', 'I', 7)
            pdf.set_text_color(150, 150, 150)
            pdf.cell(0, 4, f'Created: {n.get("created_at", "")}', new_x='LMARGIN', new_y='NEXT')
            pdf.ln(4)

    conn.close()

    # Save to reports directory
    reports_dir = os.path.join(os.path.dirname(__file__), 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    filename = f'forensic_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf'
    filepath = os.path.join(reports_dir, filename)
    pdf.output(filepath)

    return filepath, filename
