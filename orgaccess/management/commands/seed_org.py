"""
Generate the mock company: Brightline Distribution Ltd.

7 departments x 50 staff + a 7-person Executive Office = 357 staff.
Per department: 1 head, 4 managers, 10 supervisors, 30 officers, 5 juniors.
Fully synthetic and deterministic (same --seed gives the same company).

    python manage.py seed_org            # first time
    python manage.py seed_org --reset    # wipe and regenerate
"""
import random

from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from orgaccess import catalog
from orgaccess.models import (
    AccessGroup, AuditLog, Department, Document, DocumentChunk, Level, PrivateItem, Role,
    Sensitivity, TemporaryGrant, Tool, ToolGrant, User,DataSource,
DataSourceAccessMode,
DataSourceType,
)
from orgaccess.services.document_acl import create_document_chunk

FIRST = ["Chinedu", "Amaka", "Tunde", "Ngozi", "Emeka", "Funke", "Ibrahim", "Aisha", "Segun", "Bisi",
         "Uche", "Ifeoma", "Kelechi", "Yetunde", "Obinna", "Zainab", "Femi", "Chioma", "Musa", "Halima",
         "Sola", "Kemi", "Ikenna", "Nneka", "Dayo", "Hauwa", "Tobi", "Sade", "Efe", "Ose"]
LAST = ["Okafor", "Adeyemi", "Bello", "Eze", "Balogun", "Ogunleye", "Nwosu", "Abubakar", "Okonkwo", "Ibrahim",
        "Adebayo", "Chukwu", "Lawal", "Olawale", "Umeh", "Danjuma", "Obi", "Akinola", "Yusuf", "Nnamdi",
        "Ojo", "Ndukwe", "Salami", "Igwe", "Afolabi", "Musa", "Okoye", "Ajayi", "Onyema", "Garba"]

# code, name, reports-to (exec role code), titles for levels 2..6
DEPARTMENTS = [
    ("sales", "Sales", "md", ("Head of Sales", "Sales Manager", "Sales Supervisor", "Sales Executive", "Sales Assistant")),
    ("procurement", "Procurement", "coo", ("Head of Procurement", "Procurement Manager", "Procurement Supervisor", "Procurement Officer", "Procurement Assistant")),
    ("warehouse", "Warehouse and Logistics", "coo", ("Head of Logistics", "Warehouse Manager", "Shift Supervisor", "Warehouse Officer", "Loader / Driver")),
    ("finance", "Finance", "cfo", ("Head of Finance", "Finance Manager", "Senior Accountant", "Accounts Officer", "Accounts Clerk")),
    ("hr", "Human Resources", "md", ("Head of HR", "HR Manager", "HR Supervisor", "HR Officer", "HR Assistant")),
    ("customer-service", "Customer Service", "md", ("Head of Customer Service", "Customer Service Manager", "Team Lead", "Customer Service Agent", "Trainee Agent")),
    ("it", "IT", "coo", ("Head of IT", "IT Manager", "IT Supervisor", "IT Officer", "IT Support Assistant")),
]
PER_LEVEL = {2: 1, 3: 4, 4: 10, 5: 30, 6: 5}  # 50 per department
LEVEL_SLUG = {2: "head", 3: "manager", 4: "supervisor", 5: "officer", 6: "junior"}

EXEC_ROLES = [("md", "Managing Director"), ("cfo", "Chief Financial Officer"), ("coo", "Chief Operating Officer"),
              ("chief-of-staff", "Chief of Staff"), ("company-secretary", "Company Secretary")]

GROUPS = {
    "payroll-team": "Can open payslips and the payroll register",
    "hr-casework": "Can open HR disciplinary and grievance files",
    "finance-approvers": "Authorised to approve payments",
    "auditors": "Read-only company-wide review; every read is logged",
    "dpo": "Data protection officer access to personal-data records",
    "it-admins": "Can fulfil access requests (no business-content access)",
}


class Command(BaseCommand):
    help = "Generate the synthetic Brightline Distribution org."

    def add_arguments(self, parser):
        parser.add_argument("--seed", type=int, default=42)
        parser.add_argument("--reset", action="store_true")

    @transaction.atomic
    def handle(self, *args, **opts):
        if opts["reset"]:
            self._wipe()
        elif Department.objects.exists():
            raise CommandError("Org data already exists. Use --reset to regenerate.")

        self.rng = random.Random(opts["seed"])
        self.counter = 0
        self.pw = make_password("brightline-demo")  # one hash for all demo users (dev only)

        depts = {c: Department.objects.create(code=c, name=n) for c, n, _, _ in DEPARTMENTS}
        exec_dept = Department.objects.create(code="exec-office", name="Executive Office")
        groups = {c: AccessGroup.objects.create(code=c, description=d) for c, d in GROUPS.items()}

        # tools and grants
        tools = {n: Tool.objects.create(name=n, tier=t, description=d) for n, t, d in catalog.TOOLS}
        all_depts = {**depts, "exec-office": exec_dept}
        sources = {
            code: DataSource.objects.create(
                code=f"{code}-documents",
                name=f"{dept.name} Document Collection",
                source_type=DataSourceType.DOCUMENT_COLLECTION,
                owner_department=dept,
                access_mode=DataSourceAccessMode.ITEM_ACL,
                minimum_level=Level.JUNIOR,
            )
            for code, dept in all_depts.items()
        }

        sources["company-policies"] = DataSource.objects.create(
            code="company-policies",
            name="Company Policies and General Documentation",
            source_type=DataSourceType.DOCUMENT_COLLECTION,
            owner_department=exec_dept,
            access_mode=DataSourceAccessMode.COMPANY,
            minimum_level=Level.JUNIOR,
        )
        for g in catalog.GRANTS:
            lo, hi = g["levels"]
            ToolGrant.objects.create(
                tool=tools[g["tool"]], level_min=lo, level_max=hi,
                department=all_depts[g["dept"]] if g.get("dept") else None,
                required_group=groups[g["group"]] if g.get("group") else None,
                scope=g.get("scope", "self"), approval_limit_ngn=g.get("limit"),
                requires_second_approver=g.get("second", False),
            )

        # executive office
        execs = {}
        for code, title in EXEC_ROLES:
            role = Role.objects.create(code=code, title=title, department=exec_dept, level=Level.EXECUTIVE)
            execs[code] = self._user(role, exec_dept, None)
        aud_role = Role.objects.create(code="internal-auditor", title="Internal Auditor", department=exec_dept, level=Level.SUPERVISOR)
        dpo_role = Role.objects.create(code="dpo-officer", title="Data Protection Officer", department=exec_dept, level=Level.SUPERVISOR)
        auditor = self._user(aud_role, exec_dept, execs["md"])
        dpo = self._user(dpo_role, exec_dept, execs["company-secretary"])
        auditor.access_groups.add(groups["auditors"])
        dpo.access_groups.add(groups["dpo"])

        # departments
        staff = {}
        for code, name, boss, titles in DEPARTMENTS:
            dept = depts[code]
            roles = {lvl: Role.objects.create(code=f"{code}-{LEVEL_SLUG[lvl]}", title=titles[lvl - 2], department=dept, level=lvl)
                     for lvl in range(2, 7)}
            head = self._user(roles[2], dept, execs[boss])
            managers = [self._user(roles[3], dept, head) for _ in range(PER_LEVEL[3])]
            sups = [self._user(roles[4], dept, managers[i % len(managers)]) for i in range(PER_LEVEL[4])]
            officers = [self._user(roles[5], dept, sups[i % len(sups)]) for i in range(PER_LEVEL[5])]
            juniors = [self._user(roles[6], dept, sups[i % len(sups)]) for i in range(PER_LEVEL[6])]
            staff[code] = dict(head=head, managers=managers, supervisors=sups, officers=officers, juniors=juniors)

        # group memberships
        for u in staff["hr"]["officers"][:3]:
            u.access_groups.add(groups["payroll-team"])
        for u in (staff["hr"]["head"], staff["hr"]["managers"][0]):
            u.access_groups.add(groups["hr-casework"])
        for u in [execs["cfo"], staff["finance"]["head"], *staff["finance"]["managers"]]:
            u.access_groups.add(groups["finance-approvers"])
        for u in staff["it"]["officers"][:2]:
            u.access_groups.add(groups["it-admins"])

        self._documents(depts, exec_dept, groups, sources)
        self._private_items(staff)

        n_users = User.objects.exclude(employee_id=None).count()
        self.stdout.write(self.style.SUCCESS(
            f"Seeded {n_users} staff, {Department.objects.count()} departments, "
            f"{Tool.objects.count()} tools, {ToolGrant.objects.count()} grants, "
            f"{Document.objects.count()} documents, {DocumentChunk.objects.count()} chunks."))

    # ---------- helpers ----------

    def _wipe(self):
        for m in (AuditLog, TemporaryGrant, PrivateItem, DocumentChunk, Document, DataSource, ToolGrant, Tool):
            m.objects.all().delete()
        User.objects.exclude(employee_id=None).delete()
        for m in (Role, Department, AccessGroup):
            m.objects.all().delete()

    def _user(self, role, dept, manager):
        self.counter += 1
        first, last = self.rng.choice(FIRST), self.rng.choice(LAST)
        u = User(
            username=f"{first}.{last}.{self.counter}".lower(), first_name=first, last_name=last,
            email=f"{first}.{last}.{self.counter}@brightline.example".lower(),
            employee_id=f"BL{self.counter:04d}", role=role, department=dept, manager=manager,
        )
        u.password = self.pw
        u.save()
        return u

    def _doc(self, title, body, dept, sens, data_source, owner=None, subject=None, groups=()):
        doc = Document.objects.create(
            title=title,
            body=body,
            department=dept,
            sensitivity=sens,
            owner=owner,
            subject=subject,
            source="seed",
            data_source=data_source,
        )

        # Assign the complete parent ACL before creating chunks.
        doc.allowed_groups.set(groups)

        half = max(1, len(body) // 2)
        chunk_texts = (body[:half], body[half:] or body)

        for position, text in enumerate(chunk_texts):
            create_document_chunk(
                document=doc,
                position=position,
                text=text,
            )

        return doc

    def _documents(self, depts, exec_dept, groups, sources):
        S = Sensitivity

        company_source = sources["company-policies"]

        self._doc(
            "Code of Conduct",
            "Synthetic code of conduct for all staff.",
            None,
            S.PUBLIC,
            company_source,
        )

        for t in ("Leave Policy", "Expense Policy", "Data Protection Policy"):
            self._doc(
                t,
                f"Synthetic {t.lower()} for all staff.",
                None,
                S.INTERNAL,
                company_source,
            )

        for code, dept in depts.items():
            n = dept.name

            self._doc(
                f"{n} SOP",
                f"Standard operating procedures for {n}.",
                dept,
                S.INTERNAL,
                sources[code],
            )

            self._doc(
                f"{n} Team Handbook",
                f"Internal handbook for the {n} team.",
                dept,
                S.DEPARTMENTAL,
                sources[code],
            )

            self._doc(
                f"{n} Weekly Report",
                f"Weekly activity report for {n}.",
                dept,
                S.DEPARTMENTAL,
                sources[code],
            )

            self._doc(
                f"{n} Budget and Targets",
                f"Budget and targets for {n}.",
                dept,
                S.CONFIDENTIAL,
                sources[code],
            )

        self._doc(
            "Supplier Contracts 2026",
            "Synthetic supplier contract terms and prices.",
            depts["procurement"],
            S.CONFIDENTIAL,
            sources["procurement"],
        )

        self._doc(
            "General Ledger Summary",
            "Synthetic general ledger summary.",
            depts["finance"],
            S.CONFIDENTIAL,
            sources["finance"],
        )

        self._doc(
            "Board Pack Q3",
            "Synthetic board pack.",
            exec_dept,
            S.CONFIDENTIAL,
            sources["exec-office"],
        )

        self._doc(
            "Payroll Register",
            "Synthetic payroll register for all staff.",
            depts["hr"],
            S.RESTRICTED,
            sources["hr"],
            groups=[groups["payroll-team"], groups["dpo"]],
        )

        self._doc(
            "Disciplinary Case File HR-017",
            "Synthetic disciplinary case file.",
            depts["hr"],
            S.RESTRICTED,
            sources["hr"],
            groups=[groups["hr-casework"], groups["dpo"]],
        )

        for u in User.objects.exclude(employee_id=None):
            self._doc(
                f"Payslip {u.employee_id}",
                f"Synthetic payslip for {u.get_full_name()}.",
                depts["hr"],
                S.RESTRICTED,
                sources["hr"],
                subject=u,
                groups=[groups["payroll-team"]],
            )

    def _private_items(self, staff):
        for dept in staff.values():
            for u in (dept["head"], dept["managers"][0], dept["officers"][0]):
                PrivateItem.objects.create(owner=u, kind="chat", content=f"Private chat history of {u.employee_id}.")
