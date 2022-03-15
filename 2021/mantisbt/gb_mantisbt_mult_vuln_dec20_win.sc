CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145168" );
	script_version( "2021-08-26T06:01:00+0000" );
	script_tag( name: "last_modification", value: "2021-08-26 06:01:00 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-01-15 07:16:25 +0000 (Fri, 15 Jan 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 19:43:00 +0000 (Mon, 04 Jan 2021)" );
	script_cve_id( "CVE-2020-28413", "CVE-2020-35849", "CVE-2020-29603", "CVE-2020-29604", "CVE-2020-29605", "CVE-2020-35571" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MantisBT < 2.24.4 Multiple Vulnerabilities - Windows" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mantisbt/detected", "Host/runs_windows" );
	script_tag( name: "summary", value: "MantisBT is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - SQL Injection can occur in the parameter 'access' of the mc_project_get_users function through the API SOAP. (CVE-2020-28413)

  - Incorrect access check in bug_revision_view_page.php allows an unprivileged attacker to view the Summary
    field of private issues, as well as bugnotes revisions, gaining access to potentially confidential
    information via the bugnote_id parameter. (CVE-2020-35849)

  - In manage_proj_edit_page.php any unprivileged logged-in user can retrieve Private Projects' names via the
    manage_proj_edit_page.php project_id parameter, without having access to them. (CVE-2020-29603)

  - A missing access check in bug_actiongroup.php allows an attacker (with rights to create new issues) to use
    the COPY group action to create a clone, including all bugnotes and attachments, of any private issue
    (i.e., one having Private view status, or belonging to a private Project) via the bug_arr[] parameter.
    This provides full access to potentially confidential information. (CVE-2020-29604)

  - Due to insufficient access-level checks, any logged-in user allowed to perform Group Actions can get access
    to the Summary fields of private Issues via bug_arr[]= in a crafted bug_actiongroup_page.php URL. (The
    target Issues can have Private view status, or belong to a private Project.) (CVE-2020-29605)

  - There are several calls to helper_ensure_confirmed() that output unsanitized user data,
    which could potentially lead to XSS attacks. (CVE-2020-35571)" );
	script_tag( name: "affected", value: "MantisBT versions 2.24.3 and probably prior." );
	script_tag( name: "solution", value: "Update to version 2.24.4 or later." );
	script_xref( name: "URL", value: "https://www.mantisbt.org/bugs/view.php?id=27495" );
	script_xref( name: "URL", value: "https://www.mantisbt.org/bugs/view.php?id=27370" );
	script_xref( name: "URL", value: "https://ethicalhcop.medium.com/cve-2020-28413-blind-sql-injection-en-mantis-bug-tracker-2-24-3-api-soap-54238f8e046d" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=27357" );
	script_xref( name: "URL", value: "https://mantisbt.org/bugs/view.php?id=27779" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "2.24.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.24.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

