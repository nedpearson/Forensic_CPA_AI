const { Client } = require('pg');

const urls = [
    'postgresql://postgres.your-tenant-id:1236ece2b817b9c8241d204edc004911b29405978a42b7cff4e956b26a919b14@209.38.153.191:5432/postgres',
    'postgresql://postgres.your-tenant-id:1236ece2b817b9c8241d204edc004911b29405978a42b7cff4e956b26a919b14D@209.38.153.191:5432/postgres'
];

async function test_all() {
    for (const connectionString of urls) {
        console.log("Testing:", connectionString);
        const client = new Client({ connectionString });
        try {
            await client.connect();
            const res = await client.query("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'");
            const prefixes = new Set();
            res.rows.forEach(r => {
                if (r.table_name.includes('_')) {
                    prefixes.add(r.table_name.split('_')[0] + '_');
                }
            });
            console.log('SUCCESS! Prefixes:', Array.from(prefixes));
            await client.end();
            return;
        } catch (err) {
            console.log("FAILED:", err.message);
        }
    }
}
test_all();
