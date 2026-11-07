from datetime import timedelta
from decimal import Decimal
from django.core.exceptions import ValidationError, PermissionDenied
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
    AccessGroup,
    DataSource,
    DataSourceAccessMode,
    DataSourceType,
    Department,
    Document,
    DocumentChunk,
    Level,
    PrivateItem,
    Role,
    Sensitivity,
    Scope,
    TemporaryGrant,
    User,
    AuditLog
)

from .services.source_access import (
    data_sources_for_user,
    resolve_data_source_access,
)

from .services.document_acl import (
    create_document_chunk,
    update_document_acl,
)

from .services.tool_scope import (
    filter_queryset_for_scope,
    resolve_tool_scope,
)

from .services.data_access import (
    get_document_for_user,
    search_chunks_for_user,
    search_documents_for_user,
)

from .services.private_data import (
    create_private_item_for_user,
    delete_private_item_for_user,
    get_private_item_for_user,
    list_private_items_for_user,
    update_private_item_for_user,
)

from .services.document_acl import create_document_chunk

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

    def make_data_source(
            self,
            *,
            code,
            owner_department,
            access_mode,
            minimum_level,
            is_active=True,
    ):
        return DataSource.objects.create(
            code=code,
            name=code.replace("-", " ").title(),
            source_type=DataSourceType.DOCUMENT_COLLECTION,
            owner_department=owner_department,
            access_mode=access_mode,
            minimum_level=minimum_level,
            is_active=is_active,
        )

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

    def test_runtime_discovery_preserves_multiple_grants(self):
        head = staff("sales", Level.DEPT_HEAD)

        original = tools_for(head)
        available = available_tools_for(head)

        self.assertIn("query_metrics", available)

        self.assertEqual(
            original["query_metrics"],
            available["query_metrics"],
        )

        self.assertEqual(
            scopes_for(head, "query_metrics"),
            {"department", "company_aggregate"},
        )

    def test_scope_requires_matching_tool_grant(self):
        junior = staff("warehouse", Level.JUNIOR)

        with self.assertRaises(PermissionDenied):
            resolve_tool_scope(
                junior,
                "get_ar_ap_aging",
                Scope.DEPARTMENT,
            )

    def test_self_scope_limits_records_to_requester(self):
        junior = staff("warehouse", Level.JUNIOR)

        context = resolve_tool_scope(
            junior,
            "get_my_tasks",
            Scope.SELF,
        )

        result = filter_queryset_for_scope(
            User.objects.all(),
            context,
            user_field="pk",
        )

        self.assertEqual(
            set(result.values_list("pk", flat=True)),
            {junior.pk},
        )

    def test_team_scope_limits_records_to_reporting_line(self):
        manager = staff("sales", Level.MANAGER)

        context = resolve_tool_scope(
            manager,
            "get_team_status",
            Scope.TEAM,
        )

        result = filter_queryset_for_scope(
            User.objects.all(),
            context,
            user_field="pk",
        )

        actual_ids = set(result.values_list("pk", flat=True))
        expected_ids = report_ids(manager)

        self.assertSetEqual(actual_ids, expected_ids)
        self.assertNotIn(manager.pk, actual_ids)

    def test_department_scope_limits_records_to_own_department(self):
        manager = staff("finance", Level.MANAGER)

        context = resolve_tool_scope(
            manager,
            "get_budget_status",
            Scope.DEPARTMENT,
        )

        result = filter_queryset_for_scope(
            User.objects.all(),
            context,
            department_field="department_id",
        )

        expected_ids = set(
            User.objects.filter(
                department=manager.department
            ).values_list("pk", flat=True)
        )

        actual_ids = set(result.values_list("pk", flat=True))

        self.assertSetEqual(actual_ids, expected_ids)

    def test_company_aggregate_rejects_raw_queryset_access(self):
        head = staff("sales", Level.DEPT_HEAD)

        context = resolve_tool_scope(
            head,
            "query_metrics",
            Scope.COMPANY_AGGREGATE,
        )

        self.assertTrue(context.aggregate_only)

        with self.assertRaises(PermissionDenied):
            filter_queryset_for_scope(
                User.objects.all(),
                context,
                user_field="pk",
            )

    def test_acl_scope_rejects_non_access_controlled_models(self):
        junior = staff("warehouse", Level.JUNIOR)

        context = resolve_tool_scope(
            junior,
            "search_policies",
            Scope.ACL,
        )

        with self.assertRaises(PermissionDenied):
            filter_queryset_for_scope(
                User.objects.all(),
                context,
            )

    def test_acl_scope_uses_visible_to(self):
        junior = staff("warehouse", Level.JUNIOR)

        context = resolve_tool_scope(
            junior,
            "search_policies",
            Scope.ACL,
        )

        result = filter_queryset_for_scope(
            Document.objects.all(),
            context,
        )

        expected_ids = set(
            visible_to(
                junior,
                Document.objects.all(),
            ).values_list("pk", flat=True)
        )

        actual_ids = set(result.values_list("pk", flat=True))

        self.assertSetEqual(actual_ids, expected_ids)

        self.assertFalse(
            result.filter(title="Payroll Register").exists()
        )

    def test_company_scope_does_not_override_document_acl(self):
        md = User.objects.get(role__code="md")

        context = resolve_tool_scope(
            md,
            "query_metrics",
            Scope.COMPANY,
        )

        result = filter_queryset_for_scope(
            Document.objects.all(),
            context,
        )

        expected_ids = set(
            visible_to(
                md,
                Document.objects.all(),
            ).values_list("pk", flat=True)
        )

        actual_ids = set(result.values_list("pk", flat=True))

        self.assertSetEqual(actual_ids, expected_ids)

        self.assertFalse(
            result.filter(title="Payroll Register").exists()
        )

    def test_scope_resolver_rejects_stale_inactive_user(self):
        user = staff("sales", Level.MANAGER)

        stale_user = User.objects.get(pk=user.pk)

        User.objects.filter(pk=user.pk).update(is_active=False)

        with self.assertRaises(PermissionDenied):
            resolve_tool_scope(
                stale_user,
                "get_team_status",
                Scope.TEAM,
            )

    def test_document_access_requires_tool_authorization(self):
        junior = staff("warehouse", Level.JUNIOR)

        with self.assertRaises(PermissionDenied):
            search_documents_for_user(
                user=junior,
                query="Warehouse",
                tool_name="search_documents",
            )

        self.assertTrue(
            AuditLog.objects.filter(
                user=junior,
                action="document.access.denied",
                allowed=False,
            ).exists()
        )

    def test_document_search_returns_only_authorized_documents(self):
        officer = staff("sales", Level.OFFICER)

        results = search_documents_for_user(
            user=officer,
            query="Weekly Report",
            tool_name="search_documents",
        )

        titles = {document.title for document in results}

        self.assertIn("Sales Weekly Report", titles)
        self.assertNotIn("Finance Weekly Report", titles)

        self.assertTrue(
            AuditLog.objects.filter(
                user=officer,
                action="document.search",
                allowed=True,
            ).exists()
        )

    def test_document_retrieval_denies_restricted_documents(self):
        junior = staff("warehouse", Level.JUNIOR)

        payroll = doc("Payroll Register")

        with self.assertRaises(PermissionDenied):
            get_document_for_user(
                user=junior,
                document_id=payroll.pk,
                tool_name="search_policies",
            )

        self.assertTrue(
            AuditLog.objects.filter(
                user=junior,
                action="document.read",
                allowed=False,
                object_ids=str(payroll.pk),
            ).exists()
        )

    def test_chunk_search_enforces_parent_document_acl(self):
        junior = staff("warehouse", Level.JUNIOR)

        payroll = doc("Payroll Register")

        # Simulate an incorrectly permissive chunk ACL.
        DocumentChunk.objects.filter(
            document=payroll
        ).update(
            department=None,
            sensitivity=Sensitivity.PUBLIC,
            owner=None,
            subject=None,
        )

        for chunk in payroll.chunks.all():
            chunk.allowed_groups.clear()

        results = search_chunks_for_user(
            user=junior,
            query="payroll",
            tool_name="search_policies",
        )

        self.assertFalse(
            any(
                chunk.document_id == payroll.pk
                for chunk in results
            )
        )

    def test_private_data_service_only_returns_owners_items(self):
        manager = staff("sales", Level.MANAGER)
        officer = staff("sales", Level.OFFICER)

        other_item = PrivateItem.objects.create(
            owner=officer,
            kind="note",
            content="Officer's private note",
        )

        results = list_private_items_for_user(user=manager)

        self.assertTrue(
            all(
                item.id != other_item.pk
                for item in results
            )
        )

        self.assertTrue(
            all(
                item.id in PrivateItem.objects.filter(
                    owner=manager
                ).values_list("pk", flat=True)
                for item in results
            )
        )

    def test_private_data_service_denies_cross_user_retrieval(self):
        manager = staff("sales", Level.MANAGER)
        officer = staff("sales", Level.OFFICER)

        item = create_private_item_for_user(
            user=officer,
            kind="note",
            content="Confidential personal note",
        )

        with self.assertRaises(PermissionDenied):
            get_private_item_for_user(
                user=manager,
                item_id=item.id,
            )

        self.assertTrue(
            AuditLog.objects.filter(
                user=manager,
                action="private_item.read",
                allowed=False,
                object_ids=str(item.id),
            ).exists()
        )

    def test_private_item_creation_assigns_authenticated_owner(self):
        manager = staff("sales", Level.MANAGER)

        result = create_private_item_for_user(
            user=manager,
            kind="preference",
            content="Prefers concise operational reports.",
        )

        item = PrivateItem.objects.get(pk=result.id)

        self.assertEqual(item.owner_id, manager.pk)
        self.assertEqual(item.kind, "preference")

    def test_inactive_user_cannot_access_private_data_service(self):
        manager = staff("sales", Level.MANAGER)

        manager.private_items.create(
            kind="note",
            content="Private note",
        )

        manager.is_active = False
        manager.save()

        with self.assertRaises(PermissionDenied):
            list_private_items_for_user(user=manager)

        with self.assertRaises(PermissionDenied):
            create_private_item_for_user(
                user=manager,
                kind="note",
                content="Another note",
            )

    def test_private_item_owner_can_update_and_delete(self):
        manager = staff("sales", Level.MANAGER)

        created = create_private_item_for_user(
            user=manager,
            kind="note",
            content="Original note",
        )

        updated = update_private_item_for_user(
            user=manager,
            item_id=created.id,
            content="Updated note",
        )

        self.assertEqual(updated.content, "Updated note")

        delete_private_item_for_user(
            user=manager,
            item_id=created.id,
        )

        self.assertFalse(
            PrivateItem.objects.filter(pk=created.id).exists()
        )

    def test_department_source_requires_matching_department_and_level(self):
        sales_manager = staff("sales", Level.MANAGER)
        sales_officer = staff("sales", Level.OFFICER)
        procurement_manager = staff("procurement", Level.MANAGER)

        source = self.make_data_source(
            code="sales-management-data",
            owner_department=sales_manager.department,
            access_mode=DataSourceAccessMode.DEPARTMENT,
            minimum_level=Level.MANAGER,
        )

        self.assertEqual(
            resolve_data_source_access(sales_manager, source).source.pk,
            source.pk,
        )

        with self.assertRaises(PermissionDenied):
            resolve_data_source_access(sales_officer, source)

        with self.assertRaises(PermissionDenied):
            resolve_data_source_access(procurement_manager, source)

    def test_company_source_allows_other_departments_within_level(self):
        finance_manager = staff("finance", Level.MANAGER)
        sales_manager = staff("sales", Level.MANAGER)
        sales_officer = staff("sales", Level.OFFICER)

        source = self.make_data_source(
            code="company-management-reports",
            owner_department=finance_manager.department,
            access_mode=DataSourceAccessMode.COMPANY,
            minimum_level=Level.MANAGER,
        )

        self.assertTrue(
            data_sources_for_user(sales_manager).filter(
                pk=source.pk
            ).exists()
        )

        with self.assertRaises(PermissionDenied):
            resolve_data_source_access(sales_officer, source)

    def test_item_acl_source_defers_record_access_to_item_permissions(self):
        sales_supervisor = staff("sales", Level.SUPERVISOR)
        sales_officer = staff("sales", Level.OFFICER)

        source = self.make_data_source(
            code="hr-personnel-records",
            owner_department=Department.objects.get(code="hr"),
            access_mode=DataSourceAccessMode.ITEM_ACL,
            minimum_level=Level.SUPERVISOR,
        )

        access = resolve_data_source_access(
            sales_supervisor,
            source,
        )

        self.assertTrue(access.requires_item_acl)

        with self.assertRaises(PermissionDenied):
            resolve_data_source_access(sales_officer, source)

    def test_inactive_data_source_is_denied(self):
        manager = staff("sales", Level.MANAGER)

        source = self.make_data_source(
            code="inactive-sales-source",
            owner_department=manager.department,
            access_mode=DataSourceAccessMode.DEPARTMENT,
            minimum_level=Level.JUNIOR,
            is_active=False,
        )

        with self.assertRaises(PermissionDenied):
            resolve_data_source_access(manager, source)

    def test_inactive_user_cannot_access_data_sources(self):
        manager = staff("sales", Level.MANAGER)

        source = self.make_data_source(
            code="sales-data",
            owner_department=manager.department,
            access_mode=DataSourceAccessMode.DEPARTMENT,
            minimum_level=Level.JUNIOR,
        )

        stale_user = User.objects.get(pk=manager.pk)

        User.objects.filter(pk=manager.pk).update(
            is_active=False
        )

        with self.assertRaises(PermissionDenied):
            resolve_data_source_access(stale_user, source)

    def test_data_source_discovery_filters_by_user_permissions(self):
        sales_manager = staff("sales", Level.MANAGER)

        sales_source = self.make_data_source(
            code="sales-data",
            owner_department=sales_manager.department,
            access_mode=DataSourceAccessMode.DEPARTMENT,
            minimum_level=Level.JUNIOR,
        )

        finance_source = self.make_data_source(
            code="finance-data",
            owner_department=Department.objects.get(code="finance"),
            access_mode=DataSourceAccessMode.DEPARTMENT,
            minimum_level=Level.JUNIOR,
        )

        discovered_ids = set(
            data_sources_for_user(sales_manager).values_list(
                "pk",
                flat=True,
            )
        )

        self.assertIn(sales_source.pk, discovered_ids)
        self.assertNotIn(finance_source.pk, discovered_ids)

    def test_seeded_documents_have_registered_sources(self):
        self.assertEqual(DataSource.objects.count(), 9)

        self.assertEqual(
            Document.objects.filter(data_source__isnull=True).count(),
            0,
        )

        self.assertEqual(Document.objects.count(), 394)

    def test_document_without_registered_source_is_denied(self):
        junior = staff("warehouse", Level.JUNIOR)

        document = Document.objects.create(
            title="Unregistered Public Document",
            body="This document has no registered data source.",
            sensitivity=Sensitivity.PUBLIC,
        )

        with self.assertRaises(PermissionDenied):
            get_document_for_user(
                user=junior,
                document_id=document.pk,
                tool_name="search_policies",
            )

        results = search_documents_for_user(
            user=junior,
            query="Unregistered Public Document",
            tool_name="search_policies",
        )

        self.assertFalse(
            any(result.id == document.pk for result in results)
        )

    def test_source_access_and_document_acl_are_both_required(self):
        sales_manager = staff("sales", Level.MANAGER)
        finance = Department.objects.get(code="finance")

        source = self.make_data_source(
            code="finance-restricted-source",
            owner_department=finance,
            access_mode=DataSourceAccessMode.DEPARTMENT,
            minimum_level=Level.JUNIOR,
        )

        # PUBLIC would ordinarily permit all active users to see this.
        document = Document.objects.create(
            title="Finance Source Boundary Test",
            body="Synthetic financial information.",
            department=finance,
            sensitivity=Sensitivity.PUBLIC,
            data_source=source,
        )

        with self.assertRaises(PermissionDenied):
            get_document_for_user(
                user=sales_manager,
                document_id=document.pk,
                tool_name="search_policies",
            )

    def test_item_acl_source_preserves_cross_department_payslip_access(self):
        employee = staff("sales", Level.OFFICER, 0)
        another_employee = staff("sales", Level.OFFICER, 1)

        own_payslip = payslip_of(employee)
        another_payslip = payslip_of(another_employee)

        result = get_document_for_user(
            user=employee,
            document_id=own_payslip.pk,
            tool_name="search_policies",
        )

        self.assertEqual(result.id, own_payslip.pk)
        self.assertEqual(result.data_source_code, "hr-documents")

        with self.assertRaises(PermissionDenied):
            get_document_for_user(
                user=employee,
                document_id=another_payslip.pk,
                tool_name="search_policies",
            )

    def test_chunk_search_enforces_source_policy(self):
        sales_manager = staff("sales", Level.MANAGER)
        finance = Department.objects.get(code="finance")

        source = self.make_data_source(
            code="finance-chunk-boundary",
            owner_department=finance,
            access_mode=DataSourceAccessMode.DEPARTMENT,
            minimum_level=Level.JUNIOR,
        )

        document = Document.objects.create(
            title="Finance Chunk Boundary",
            body="",
            department=finance,
            sensitivity=Sensitivity.PUBLIC,
            data_source=source,
        )

        create_document_chunk(
            document=document,
            position=0,
            text="unique-finance-source-boundary-marker",
        )

        results = search_chunks_for_user(
            user=sales_manager,
            query="unique-finance-source-boundary-marker",
            tool_name="search_policies",
        )

        self.assertFalse(
            any(
                result.document_id == document.pk
                for result in results
            )
        )

