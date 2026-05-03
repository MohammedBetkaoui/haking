const { generateMonthlyReport, getMonthKey, getPreviousMonthDate } = require('../services/reporting');

async function runMonthlyReportJob() {
  const previousMonth = getPreviousMonthDate();
  return generateMonthlyReport({ month: getMonthKey(previousMonth) });
}

module.exports = { runMonthlyReportJob };