$env:CYBERASSETIQ_BACKEND_URL="http://192.168.0.179:8000"
$env:CYBERASSETIQ_TENANT_ID="tenant-001"
$env:CYBERASSETIQ_API_KEY="ciq_pd8ksmM393xTvSMwf3H9u2SHbkSXuNbcpkRABzMzOds"
$env:CYBERASSETIQ_ENROLLMENT_TOKEN=""
$env:CYBERASSETIQ_AGENT_ID="agent-tenant-001-810572997e47ab2b"
$env:CYBERASSETIQ_POLL_INTERVAL="300"
$env:CYBERASSETIQ_QUEUE_DB="./data/agent_queue.db"
$env:CYBERASSETIQ_VERIFY_TLS="false"
$env:CYBERASSETIQ_LOG_LEVEL="INFO"
$env:SECRETSCORE_MODEL_PATH="C:\tmp\cyberassetiq_secretscore.pkl"
$env:CYBERASSETIQ_COMMAND_POLL_INTERVAL="60"
$oldProcess = Get-NetTCPConnection -LocalPort 8099 -ErrorAction SilentlyContinue
if ($oldProcess) {
    Stop-Process -Id $oldProcess.OwningProcess -Force -ErrorAction SilentlyContinue
}
Start-Sleep 2
python -m uvicorn service.main:app --host 0.0.0.0 --port 8099