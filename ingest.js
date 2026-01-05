const { run } = require('./src/lib/ingest/nvd');

console.log("Starting manual ingestion...");

run()
  .then(() => {
    console.log("Ingestion process finished.");
    process.exit(0);
  })
  .catch((err) => {
    console.error("Ingestion failed:", err);
    process.exit(1);
  });