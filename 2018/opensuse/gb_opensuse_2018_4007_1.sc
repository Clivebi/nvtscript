if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852156" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_cve_id( "CVE-2018-10915" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-17 19:15:00 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-10 07:36:25 +0100 (Mon, 10 Dec 2018)" );
	script_name( "openSUSE: Security Advisory for postgresql94 (openSUSE-SU-2018:4007-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2018:4007-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2018-12/msg00006.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'postgresql94'
  package(s) announced via the openSUSE-SU-2018:4007-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for postgresql94 to 9.4.19 fixes
  the following security issue:

  - CVE-2018-10915: libpq failed to properly reset its internal state
  between connections. If an affected version of libpq was used with
  'host' or 'hostaddr' connection parameters from untrusted input,
  attackers could have bypassed client-side connection security features,
  obtain access to higher privileged connections or potentially cause
  other impact SQL injection, by causing the PQescape() functions to
  malfunction (bsc#1104199).

  A dump/restore is not required for this update unless you use the
  functions query_to_xml, cursor_to_xml, cursor_to_xmlschema,
  query_to_xmlschema, and query_to_xml_and_xmlschema. In this case please
  see the first entry of
  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1482=1" );
	script_tag( name: "affected", value: "postgresql94 on openSUSE Leap 42.3." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "postgresql94", rpm: "postgresql94~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib", rpm: "postgresql94-contrib~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-contrib-debuginfo", rpm: "postgresql94-contrib-debuginfo~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-debuginfo", rpm: "postgresql94-debuginfo~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-debugsource", rpm: "postgresql94-debugsource~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-devel", rpm: "postgresql94-devel~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-devel-debuginfo", rpm: "postgresql94-devel-debuginfo~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-libs-debugsource", rpm: "postgresql94-libs-debugsource~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-plperl", rpm: "postgresql94-plperl~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-plperl-debuginfo", rpm: "postgresql94-plperl-debuginfo~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-plpython", rpm: "postgresql94-plpython~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-plpython-debuginfo", rpm: "postgresql94-plpython-debuginfo~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-pltcl", rpm: "postgresql94-pltcl~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-pltcl-debuginfo", rpm: "postgresql94-pltcl-debuginfo~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server", rpm: "postgresql94-server~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-server-debuginfo", rpm: "postgresql94-server-debuginfo~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-test", rpm: "postgresql94-test~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql94-docs", rpm: "postgresql94-docs~9.4.19~24.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

