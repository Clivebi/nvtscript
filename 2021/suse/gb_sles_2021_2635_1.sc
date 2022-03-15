if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2635.1" );
	script_cve_id( "CVE-2010-2322" );
	script_tag( name: "creation_date", value: "2021-08-06 14:24:45 +0000 (Fri, 06 Aug 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2013-04-19 03:03:00 +0000 (Fri, 19 Apr 2013)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2635-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2635-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212635-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'fastjar' package(s) announced via the SUSE-SU-2021:2635-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for fastjar fixes the following issues:

CVE-2010-2322: Fixed a directory traversal vulnerabilities. (bsc#1188517)" );
	script_tag( name: "affected", value: "'fastjar' package(s) on SUSE Linux Enterprise Server 12-SP5." );
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "fastjar", rpm: "fastjar~0.98~22.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fastjar-debuginfo", rpm: "fastjar-debuginfo~0.98~22.3.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "fastjar-debugsource", rpm: "fastjar-debugsource~0.98~22.3.1", rls: "SLES12.0SP5" ) )){
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

