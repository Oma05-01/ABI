"""
Base tool catalog and role-to-tool grants.

Levels: 1 Executive, 2 Dept head, 3 Manager, 4 Supervisor, 5 Officer, 6 Junior.
A grant (level_min, level_max) is inclusive; lower number = more senior.
Every ACT tool still requires the user to confirm each action before it runs.
"""

# name, tier, description
TOOLS = [
    # ---- read ----
    ("search_policies", "read", "Search company policies and SOPs"),
    ("search_documents", "read", "Search documents the user is allowed to see"),
    ("get_my_tasks", "read", "List the user's tasks and schedule"),
    ("get_product_price", "read", "Look up product and price list"),
    ("get_team_status", "read", "Task status across the user's reporting line"),
    ("query_metrics", "read", "Query KPIs at the granted scope"),
    ("get_budget_status", "read", "Budget versus actuals for the department"),
    ("fetch_news", "read", "Fetch vetted external news relevant to the business"),
    ("get_sales_by_rep", "read", "Sales figures by representative"),
    ("get_reorder_suggestions", "read", "Stock items below reorder threshold"),
    ("get_supplier_price_history", "read", "Supplier price history"),
    ("get_bin_stock", "read", "Warehouse bin-level stock"),
    ("get_dispatch_status", "read", "Dispatch and delivery status"),
    ("get_ar_ap_aging", "read", "Receivables and payables aging"),
    ("run_reconciliation_check", "read", "Run a reconciliation check"),
    ("get_headcount", "read", "Headcount and structure"),
    ("get_leave_balances", "read", "Leave balances"),
    ("get_recruitment_pipeline", "read", "Recruitment pipeline"),
    ("get_ticket_queue", "read", "Customer ticket queue"),
    ("get_customer_history", "read", "Customer interaction history"),
    ("get_system_health", "read", "System health (no business content)"),
    ("get_access_requests", "read", "Pending access requests"),
    ("read_audit_logs", "read", "Search access and tool-call logs"),
    # ---- draft ----
    ("draft_message", "draft", "Draft an email or message"),
    ("draft_report", "draft", "Draft a daily, incident or periodic report"),
    ("summarize_meeting", "draft", "Summarize meeting notes into minutes"),
    ("draft_quote", "draft", "Draft a customer quote"),
    ("draft_purchase_request", "draft", "Draft a purchase request"),
    ("draft_customer_reply", "draft", "Draft a reply to a customer"),
    ("draft_briefing", "draft", "Draft a department or executive briefing"),
    ("draft_board_report", "draft", "Draft a board report"),
    # ---- act (human approval) ----
    ("create_ticket", "act", "Create a support or work ticket"),
    ("submit_leave_request", "act", "Submit a leave request"),
    ("update_record", "act", "Create or update a record in the user's domain"),
    ("log_stock_count", "act", "Log a stock count"),
    ("assign_task", "act", "Assign a task to someone in the reporting line"),
    ("submit_request", "act", "Submit a request for approval"),
    ("approve_request", "act", "Approve a request up to a monetary limit"),
    ("propose_payment", "act", "Propose a payment (never executes alone)"),
    ("approve_payment", "act", "Approve a proposed payment (two-person rule)"),
    ("fulfil_access_request", "act", "Fulfil an access request"),
]

# keys: tool, levels=(min, max), dept, group, scope, limit, second
GRANTS = [
    # ---- everyone (levels 1-6) ----
    dict(tool="search_policies", levels=(1, 6), scope="acl"),
    dict(tool="get_my_tasks", levels=(1, 6), scope="self"),
    dict(tool="get_product_price", levels=(1, 6)),
    dict(tool="draft_message", levels=(1, 6)),
    dict(tool="draft_report", levels=(1, 6)),
    dict(tool="create_ticket", levels=(1, 6)),
    dict(tool="submit_leave_request", levels=(1, 6), scope="self"),
    # ---- officers and above (1-5) ----
    dict(tool="search_documents", levels=(1, 5), scope="acl"),
    dict(tool="summarize_meeting", levels=(1, 5)),
    dict(tool="update_record", levels=(1, 5), scope="department"),
    # ---- supervisors and above (1-4) ----
    dict(tool="get_team_status", levels=(1, 4), scope="team"),
    dict(tool="assign_task", levels=(1, 4), scope="team"),
    dict(tool="submit_request", levels=(1, 4)),
    dict(tool="query_metrics", levels=(3, 4), scope="team"),
    # ---- managers and above (1-3) ----
    dict(tool="get_budget_status", levels=(1, 3), scope="department"),
    dict(tool="approve_request", levels=(3, 3), limit=500_000),
    # ---- department heads and executives ----
    dict(tool="query_metrics", levels=(2, 2), scope="department"),
    dict(tool="query_metrics", levels=(2, 2), scope="company_aggregate"),
    dict(tool="query_metrics", levels=(1, 1), scope="company"),
    dict(tool="fetch_news", levels=(1, 2)),
    dict(tool="draft_briefing", levels=(1, 2)),
    dict(tool="approve_request", levels=(2, 2), limit=5_000_000),
    dict(tool="approve_request", levels=(1, 1), limit=50_000_000),
    dict(tool="draft_board_report", levels=(1, 1)),
    # ---- Sales ----
    dict(tool="get_sales_by_rep", levels=(1, 5), dept="sales", scope="department"),
    dict(tool="draft_quote", levels=(1, 5), dept="sales"),
    # ---- Procurement ----
    dict(tool="get_reorder_suggestions", levels=(1, 5), dept="procurement", scope="department"),
    dict(tool="get_supplier_price_history", levels=(1, 4), dept="procurement", scope="department"),
    dict(tool="draft_purchase_request", levels=(1, 5), dept="procurement"),
    # ---- Warehouse and Logistics ----
    dict(tool="get_bin_stock", levels=(1, 6), dept="warehouse", scope="department"),
    dict(tool="get_dispatch_status", levels=(1, 6), dept="warehouse", scope="department"),
    dict(tool="log_stock_count", levels=(1, 6), dept="warehouse"),
    # ---- Finance ----
    dict(tool="get_ar_ap_aging", levels=(1, 4), dept="finance", scope="department"),
    dict(tool="run_reconciliation_check", levels=(1, 5), dept="finance", scope="department"),
    dict(tool="propose_payment", levels=(1, 5), dept="finance"),
    dict(tool="approve_payment", levels=(3, 3), dept="finance", group="finance-approvers", limit=500_000, second=True),
    dict(tool="approve_payment", levels=(2, 2), dept="finance", group="finance-approvers", limit=5_000_000, second=True),
    dict(tool="approve_payment", levels=(1, 1), dept="finance", group="finance-approvers", limit=50_000_000, second=True),
    # ---- HR ----
    dict(tool="get_headcount", levels=(1, 4), dept="hr", scope="department"),
    dict(tool="get_leave_balances", levels=(1, 5), dept="hr", scope="department"),
    dict(tool="get_recruitment_pipeline", levels=(1, 4), dept="hr", scope="department"),
    # ---- Customer Service ----
    dict(tool="get_ticket_queue", levels=(1, 6), dept="customer-service", scope="department"),
    dict(tool="get_customer_history", levels=(1, 5), dept="customer-service"),
    dict(tool="draft_customer_reply", levels=(1, 6), dept="customer-service"),
    # ---- IT (system health and access requests only, never business content) ----
    dict(tool="get_system_health", levels=(1, 5), dept="it", scope="department"),
    dict(tool="get_access_requests", levels=(1, 4), dept="it", scope="department"),
    dict(tool="fulfil_access_request", levels=(1, 5), dept="it", group="it-admins"),
    # ---- cross-cutting ----
    dict(tool="read_audit_logs", levels=(1, 6), group="auditors", scope="company"),
]
