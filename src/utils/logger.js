// Simple logger for reporting step progress in CLI
export function logStep(i, name, uses) {
  console.log(`\n[${String(i).padStart(2, '0')}] ${name}  (${uses})`);
}