if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.1423.1" );
	script_cve_id( "CVE-2020-13249" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-04-21T09:13:54+0000" );
	script_tag( name: "last_modification", value: "2021-04-21 09:13:54 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-19 13:37:27 +0200 (Mon, 19 Apr 2021)" );
	script_name( "SUSE Linux Enterprise Server: Security Advisory (SUSE-SU-2020:1423-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0LTSS)" );
	script_xref( name: "URL", value: "https://lists.suse.com/pipermail/sle-security-updates/2020-May/006859.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for 'mariadb-connector-c'
  package(s) announced via the SUSE-SU-2020:1423-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "'mariadb-connector-c' package(s) on SUSE Linux Enterprise Server 15" );
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
if(release == "SLES15.0LTSS"){
	if(!isnull( res = isrpmvuln( pkg: "libmariadb-devel", rpm: "libmariadb-devel~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb-devel-debuginfo", rpm: "libmariadb-devel-debuginfo~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb3", rpm: "libmariadb3~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb3-debuginfo", rpm: "libmariadb3-debuginfo~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb_plugins", rpm: "libmariadb_plugins~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadb_plugins-debuginfo", rpm: "libmariadb_plugins-debuginfo~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadbprivate", rpm: "libmariadbprivate~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmariadbprivate-debuginfo", rpm: "libmariadbprivate-debuginfo~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mariadb-connector-c-debugsource", rpm: "mariadb-connector-c-debugsource~3.1.8~3.18.1", rls: "SLES15.0LTSS" ) )){
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

