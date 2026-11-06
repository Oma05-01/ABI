from datetime import timedelta
from decimal import Decimal
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from .access import (
    CLEARANCE_BY_LEVEL,
    active_group_codes,
    active_group_ids,
    approval_limit,
    available_tools_for,
    can_discover_tool,
    can_use_tool,
    can_view,
    report_ids,
    scopes_for,
    tools_for,
    visible_private_items,
    visible_to,
)

from .models import (
    AccessGroup, Department, Document, DocumentChunk, Level, PrivateItem, Sensitivity,
    TemporaryGrant, User, Role
)

from .services.document_acl import (
    create_document_chunk,
    update_document_acl,
)


def staff(dept, level, n=0):
    return User.objects.filter(department__code=dept, role__level=level).order_by("id")[n]


def doc(title):
    return Document.objects.get(title=title)


def payslip_of(user):
    return Document.objects.get(title=f"Payslip {user.employee_id}")


class OrgAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        call_command("seed_org", verbosity=0)

    # ---------- shape of the mock company ----------

    def test_org_shape(self):
        regular = Department.objects.exclude(code="exec-office")
        self.assertEqual(regular.count(), 7)
        for d in regular:
            self.assertEqual(User.objects.filter(department=d).count(), 50, d.code)
            for level, expected in {2: 1, 3: 4, 4: 10, 5: 30, 6: 5}.items():
                self.assertEqual(User.objects.filter(department=d, role__level=level).count(), expected)
        self.assertEqual(User.objects.filter(department__code="exec-office").count(), 7)
        self.assertEqual(User.objects.exclude(employee_id=None).count(), 357)

    def test_reporting_lines(self):
        head = staff("sales", Level.DEPT_HEAD)
        self.assertEqual(len(report_ids(head)), 49)  # everyone else in the department
        manager = staff("sales", Level.MANAGER)
        self.assertTrue(report_ids(manager).issubset(report_ids(head)))
        self.assertNotIn(head.id, report_ids(manager))

    # ---------- the permission scenarios ----------

    def test_warehouse_junior_cannot_see_ceo_payslip(self):
        junior = staff("warehouse", Level.JUNIOR)
        md = User.objects.get(role__code="md")
        self.assertFalse(can_view(junior, payslip_of(md)))

    def test_sales_manager_cannot_see_supplier_contracts(self):
        self.assertFalse(can_view(staff("sales", Level.MANAGER), doc("Supplier Contracts 2026")))
        self.assertTrue(can_view(staff("procurement", Level.MANAGER), doc("Supplier Contracts 2026")))

    def test_finance_officer_cannot_see_hr_files(self):
        officer = staff("finance", Level.OFFICER)
        self.assertFalse(can_view(officer, doc("Human Resources Team Handbook")))
        self.assertFalse(can_view(officer, doc("Disciplinary Case File HR-017")))

    def test_payroll_needs_payroll_team(self):
        hr_officers = User.objects.filter(department__code="hr", role__level=Level.OFFICER).order_by("id")
        member, non_member = hr_officers[0], hr_officers[5]
        self.assertTrue(can_view(member, doc("Payroll Register")))
        self.assertFalse(can_view(non_member, doc("Payroll Register")))
        target = staff("sales", Level.OFFICER)
        self.assertTrue(can_view(member, payslip_of(target)))
        self.assertFalse(can_view(non_member, payslip_of(target)))

    def test_manager_cannot_read_private_items_of_reports(self):
        head = staff("sales", Level.DEPT_HEAD)
        manager = staff("sales", Level.MANAGER)
        self.assertEqual(visible_private_items(manager).exclude(owner=manager).count(), 0)
        self.assertEqual(visible_private_items(head).exclude(owner=head).count(), 0)
        self.assertGreater(PrivateItem.objects.filter(owner=manager).count(), 0)
        self.assertEqual(visible_private_items(manager).count(), PrivateItem.objects.filter(owner=manager).count())

    def test_it_admin_cannot_see_finance_content(self):
        it_admin = User.objects.filter(access_groups__code="it-admins").first()
        self.assertFalse(can_view(it_admin, doc("General Ledger Summary")))
        self.assertFalse(can_view(it_admin, doc("Finance Weekly Report")))
        self.assertTrue(can_use_tool(it_admin, "fulfil_access_request"))
        self.assertTrue(can_use_tool(it_admin, "get_system_health"))
        # IT tools expose system health and access requests, never business content
        self.assertFalse(can_use_tool(it_admin, "get_ar_ap_aging"))

    def test_mover_loses_old_department_access_immediately(self):
        user = staff("sales", Level.OFFICER, 3)

        sales_report = doc("Sales Weekly Report")

        self.assertTrue(can_view(user, sales_report))

        # Change both department and department-specific role together.
        user.department = Department.objects.get(code="procurement")
        user.role = Role.objects.get(code="procurement-officer")

        user.save(update_fields=["department", "role"])

        user = User.objects.get(pk=user.pk)

        self.assertEqual(user.department.code, "procurement")
        self.assertEqual(user.role.department.code, "procurement")

        self.assertFalse(can_view(user, sales_report))

        self.assertTrue(
            can_view(user, doc("Procurement Weekly Report"))
        )

    def test_deactivated_user_sees_nothing(self):
        user = staff("sales", Level.OFFICER, 4)
        self.assertGreater(visible_to(user, Document.objects.all()).count(), 0)
        user.is_active = False
        user.save()
        self.assertEqual(visible_to(user, Document.objects.all()).count(), 0)
        self.assertEqual(visible_private_items(user).count(), 0)
        self.assertEqual(tools_for(user), {})

    def test_everyone_sees_own_payslip_and_company_policies(self):
        for user in (staff("warehouse", Level.JUNIOR), staff("finance", Level.OFFICER), User.objects.get(role__code="cfo")):
            self.assertTrue(can_view(user, payslip_of(user)))
            self.assertTrue(can_view(user, doc("Leave Policy")))
            self.assertTrue(can_view(user, doc("Code of Conduct")))

    def test_junior_clearance_stops_at_internal(self):
        junior = staff("sales", Level.JUNIOR)
        self.assertTrue(can_view(junior, doc("Sales SOP")))            # internal
        self.assertFalse(can_view(junior, doc("Sales Team Handbook")))  # departmental needs officer+
        self.assertTrue(can_view(staff("sales", Level.OFFICER), doc("Sales Team Handbook")))

    def test_confidential_needs_manager_level(self):
        self.assertFalse(can_view(staff("sales", Level.OFFICER), doc("Sales Budget and Targets")))
        self.assertTrue(can_view(staff("sales", Level.MANAGER), doc("Sales Budget and Targets")))
        self.assertFalse(can_view(staff("finance", Level.MANAGER), doc("Sales Budget and Targets")))

    def test_executive_sees_confidential_across_departments_but_not_restricted(self):
        md = User.objects.get(role__code="md")
        self.assertTrue(can_view(md, doc("Supplier Contracts 2026")))
        self.assertTrue(can_view(md, doc("Board Pack Q3")))
        self.assertFalse(can_view(md, doc("Payroll Register")))
        self.assertFalse(can_view(md, doc("Disciplinary Case File HR-017")))
        self.assertFalse(can_view(md, payslip_of(staff("sales", Level.OFFICER))))

    def test_auditor_reads_company_wide_but_not_restricted(self):
        auditor = User.objects.get(role__code="internal-auditor")
        self.assertTrue(can_view(auditor, doc("General Ledger Summary")))
        self.assertTrue(can_view(auditor, doc("Supplier Contracts 2026")))
        self.assertFalse(can_view(auditor, doc("Payroll Register")))

    def test_break_glass_grant_expires(self):
        user = staff("finance", Level.OFFICER)
        casefile = doc("Disciplinary Case File HR-017")
        self.assertFalse(can_view(user, casefile))
        group = AccessGroup.objects.get(code="hr-casework")
        grant = TemporaryGrant.objects.create(
            user=user, group=group, reason="Test", expires_at=timezone.now() + timedelta(hours=1))
        self.assertTrue(can_view(user, casefile))
        grant.expires_at = timezone.now() - timedelta(minutes=1)
        grant.save()
        self.assertFalse(can_view(user, casefile))
        grant.expires_at = timezone.now() + timedelta(hours=1)
        grant.revoked_at = timezone.now()
        grant.save()
        self.assertFalse(can_view(user, casefile))

    def test_groups_extend_but_do_not_narrow(self):
        d = Document.objects.create(title="Project X", sensitivity=Sensitivity.INTERNAL)
        d.allowed_groups.add(AccessGroup.objects.get(code="dpo"))
        self.assertTrue(can_view(staff("sales", Level.JUNIOR), d))  # internal stays visible to all

    def test_new_documents_are_restricted_by_default(self):
        d = Document.objects.create(title="Unlabelled")
        self.assertEqual(d.sensitivity, Sensitivity.RESTRICTED)
        self.assertFalse(can_view(User.objects.get(role__code="md"), d))

    def test_chunks_inherit_document_acl(self):
        for user in (staff("sales", Level.JUNIOR), staff("sales", Level.MANAGER), staff("hr", Level.OFFICER),
                     User.objects.get(role__code="cfo")):
            doc_ids = set(visible_to(user, Document.objects.all()).values_list("id", flat=True))
            chunk_doc_ids = set(visible_to(user, DocumentChunk.objects.all()).values_list("document_id", flat=True))
            self.assertEqual(doc_ids, chunk_doc_ids, user.employee_id)

    # ---------- tools ----------

    def test_junior_has_only_basic_tools(self):
        tools = set(tools_for(staff("sales", Level.JUNIOR)))
        self.assertIn("search_policies", tools)
        self.assertIn("draft_message", tools)
        self.assertNotIn("search_documents", tools)
        self.assertNotIn("approve_request", tools)
        self.assertNotIn("get_sales_by_rep", tools)

    def test_department_tools_do_not_leak_across_departments(self):
        self.assertFalse(can_use_tool(staff("finance", Level.OFFICER), "get_ar_ap_aging"))  # supervisors and up only
        self.assertTrue(can_use_tool(staff("finance", Level.SUPERVISOR), "get_ar_ap_aging"))
        self.assertFalse(can_use_tool(staff("warehouse", Level.JUNIOR), "get_ar_ap_aging"))
        self.assertFalse(can_use_tool(staff("sales", Level.MANAGER), "get_ar_ap_aging"))
        self.assertTrue(can_use_tool(staff("warehouse", Level.JUNIOR), "log_stock_count"))

    def test_approval_limits_rise_with_seniority(self):
        self.assertIsNone(approval_limit(staff("sales", Level.OFFICER), "approve_request"))
        self.assertEqual(approval_limit(staff("sales", Level.MANAGER), "approve_request"), Decimal("500000"))
        self.assertEqual(approval_limit(staff("sales", Level.DEPT_HEAD), "approve_request"), Decimal("5000000"))
        self.assertEqual(approval_limit(User.objects.get(role__code="md"), "approve_request"), Decimal("50000000"))

    def test_payment_approval_needs_group_and_second_approver(self):
        approvers = AccessGroup.objects.get(code="finance-approvers").members.all()
        non_approver = User.objects.filter(department__code="finance", role__level=Level.MANAGER).exclude(
            pk__in=approvers.values("pk")).first()
        if non_approver:
            self.assertFalse(can_use_tool(non_approver, "approve_payment"))
        manager = staff("finance", Level.MANAGER)
        self.assertTrue(can_use_tool(manager, "approve_payment"))
        self.assertTrue(all(g.requires_second_approver for g in tools_for(manager)["approve_payment"]))

    def test_executives_get_every_departments_tools(self):
        md_tools = set(tools_for(User.objects.get(role__code="md")))
        for t in ("get_sales_by_rep", "get_ar_ap_aging", "get_bin_stock", "get_headcount", "get_system_health"):
            self.assertIn(t, md_tools)
        self.assertNotIn("read_audit_logs", md_tools)  # auditors only
        self.assertNotIn("fulfil_access_request", md_tools)  # IT admins only

    def test_metrics_scope_by_level(self):
        self.assertEqual(scopes_for(staff("sales", Level.MANAGER), "query_metrics"), {"team"})
        self.assertEqual(scopes_for(staff("sales", Level.DEPT_HEAD), "query_metrics"), {"department", "company_aggregate"})
        self.assertEqual(scopes_for(User.objects.get(role__code="md"), "query_metrics"), {"company"})
        self.assertEqual(scopes_for(staff("sales", Level.OFFICER), "query_metrics"), set())

    def test_only_auditors_read_audit_logs(self):
        self.assertTrue(can_use_tool(User.objects.get(role__code="internal-auditor"), "read_audit_logs"))
        self.assertFalse(can_use_tool(staff("it", Level.DEPT_HEAD), "read_audit_logs"))

    # ---------- independent check of the query logic ----------

    def test_query_matches_plain_python_oracle(self):
        """Re-implements the rules in plain Python and compares against visible_to() for a sample of users."""
        docs = list(Document.objects.prefetch_related("allowed_groups"))
        doc_groups = {d.id: {g.id for g in d.allowed_groups.all()} for d in docs}
        users = []
        for level in range(1, 7):
            users += list(User.objects.filter(role__level=level).order_by("id")[:6])
        users += list(User.objects.filter(access_groups__isnull=False).distinct())
        checked = 0
        for u in users:
            ids = active_group_ids(u)
            codes = active_group_codes(ids)
            clearance = CLEARANCE_BY_LEVEL[u.level]
            if "auditors" in codes:
                clearance = max(clearance, Sensitivity.CONFIDENTIAL)
            expected = set()
            for d in docs:
                ok = (
                    d.subject_id == u.id
                    or (d.owner_id == u.id and d.sensitivity < Sensitivity.RESTRICTED)
                    or bool(doc_groups[d.id] & ids)
                    or d.sensitivity <= Sensitivity.INTERNAL
                    or (
                        d.sensitivity in (Sensitivity.DEPARTMENTAL, Sensitivity.CONFIDENTIAL)
                        and d.sensitivity <= clearance
                        and (u.level == Level.EXECUTIVE or "auditors" in codes or d.department_id == u.department_id)
                    )
                )
                if ok:
                    expected.add(d.id)
            actual = set(visible_to(u, Document.objects.all()).values_list("id", flat=True))
            self.assertEqual(actual, expected, u.employee_id)
            checked += 1
        self.assertGreater(checked, 30)

    def test_document_acl_update_propagates_to_existing_chunks(self):
        document = doc("Sales Team Handbook")

        manager = staff("sales", Level.MANAGER)
        dpo = User.objects.get(role__code="dpo-officer")

        dpo_group = AccessGroup.objects.get(code="dpo")

        original_chunk_count = document.chunks.count()

        # The sales manager can initially read the departmental document.
        self.assertTrue(can_view(manager, document))

        # Restrict the document to the DPO access group.
        updated_document = update_document_acl(
            document,
            department=document.department,
            sensitivity=Sensitivity.RESTRICTED,
            owner=document.owner,
            subject=document.subject,
            allowed_groups=[dpo_group],
        )

        # The manager must lose access.
        self.assertFalse(can_view(manager, updated_document))

        # The DPO must retain access through the explicit group grant.
        self.assertTrue(can_view(dpo, updated_document))

        chunks = DocumentChunk.objects.filter(
            document=updated_document
        )

        self.assertEqual(chunks.count(), original_chunk_count)

        for chunk in chunks:
            self.assertEqual(
                chunk.department_id,
                updated_document.department_id,
            )
            self.assertEqual(
                chunk.sensitivity,
                updated_document.sensitivity,
            )
            self.assertEqual(
                chunk.owner_id,
                updated_document.owner_id,
            )
            self.assertEqual(
                chunk.subject_id,
                updated_document.subject_id,
            )

            self.assertSetEqual(
                set(chunk.allowed_groups.values_list("pk", flat=True)),
                {dpo_group.pk},
            )

        # Test actual chunk retrieval, not just field equality.
        self.assertEqual(
            visible_to(manager, chunks).count(),
            0,
        )

        self.assertEqual(
            visible_to(dpo, chunks).count(),
            original_chunk_count,
        )

    def test_new_chunk_inherits_parent_acl(self):
        document = doc("Payroll Register")

        chunk = create_document_chunk(
            document=document,
            position=999,
            text="New synthetic payroll section.",
        )

        self.assertEqual(chunk.document_id, document.pk)

        self.assertEqual(
            chunk.department_id,
            document.department_id,
        )

        self.assertEqual(
            chunk.sensitivity,
            document.sensitivity,
        )

        self.assertEqual(
            chunk.owner_id,
            document.owner_id,
        )

        self.assertEqual(
            chunk.subject_id,
            document.subject_id,
        )

        expected_groups = set(
            document.allowed_groups.values_list("pk", flat=True)
        )

        actual_groups = set(
            chunk.allowed_groups.values_list("pk", flat=True)
        )

        self.assertSetEqual(actual_groups, expected_groups)

    def test_user_department_must_match_department_bound_role(self):
        user = staff("sales", Level.OFFICER)

        user.department = Department.objects.get(code="procurement")

        with self.assertRaises(ValidationError):
            user.save()

        # Confirm the rejected update didn't reach the database.
        user.refresh_from_db()

        self.assertEqual(user.department.code, "sales")
        self.assertEqual(user.role.department.code, "sales")

    def test_role_department_cannot_change_if_it_invalidates_users(self):
        role = Role.objects.get(code="sales-officer")

        role.department = Department.objects.get(code="procurement")

        with self.assertRaises(ValidationError):
            role.save()

        role.refresh_from_db()

        self.assertEqual(role.department.code, "sales")

    def test_organization_wide_role_can_be_assigned_across_departments(self):
        generic_role = Role.objects.create(
            code="company-wide-officer",
            title="Company-wide Officer",
            department=None,
            level=Level.OFFICER,
        )

        user = staff("sales", Level.OFFICER)

        user.role = generic_role
        user.save(update_fields=["role"])

        user.refresh_from_db()

        self.assertEqual(user.department.code, "sales")
        self.assertIsNone(user.role.department_id)
        self.assertEqual(user.level, Level.OFFICER)

    def test_v1_does_not_expose_act_tools(self):
        manager = staff("finance", Level.MANAGER)

        # The organizational grant remains intact.
        self.assertTrue(
            can_use_tool(manager, "approve_payment")
        )

        self.assertIn(
            "approve_payment",
            tools_for(manager),
        )

        # But the Actor cannot discover it in version one.
        self.assertNotIn(
            "approve_payment",
            available_tools_for(manager),
        )

        self.assertFalse(
            can_discover_tool(manager, "approve_payment")
        )

    def test_v1_exposes_read_and_draft_tools(self):
        junior = staff("warehouse", Level.JUNIOR)

        available = available_tools_for(junior)

        self.assertIn("search_policies", available)
        self.assertIn("draft_message", available)

        self.assertTrue(
            can_discover_tool(junior, "search_policies")
        )

        self.assertTrue(
            can_discover_tool(junior, "draft_message")
        )

        # The junior must not receive tools they weren't granted.
        self.assertNotIn("search_documents", available)
        self.assertNotIn("approve_request", available)

    def test_inactive_user_cannot_discover_tools(self):
        user = staff("sales", Level.MANAGER)

        self.assertGreater(len(available_tools_for(user)), 0)

        user.is_active = False
        user.save()

        self.assertEqual(available_tools_for(user), {})

        self.assertFalse(
            can_discover_tool(user, "search_policies")
        )