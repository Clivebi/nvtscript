if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0792.1" );
	script_cve_id( "CVE-2014-9471" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-12-08 15:18:00 +0000 (Tue, 08 Dec 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0792-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0792-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150792-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'coreutils' package(s) announced via the SUSE-SU-2015:0792-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Coreutils was updated to fix one security issue and one non-security bug.
The following vulnerability was fixed:
Commands such as date, touch or using parse_datetime() could, when accepting untrusted input, allow an attacker to crash the application or, potentially, execute arbitrary code. (bnc#911832, CVE-2014-9471)
The following non-security bug was fixed:
df(1) executed against a bind mounted path which resided on a different file system could issue many unnecessary stat calls, causing unwanted performance issues. (bnc#919809)
Security Issues:
CVE-2014-9471" );
	script_tag( name: "affected", value: "'coreutils' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "coreutils", rpm: "coreutils~8.12~6.25.32.33.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "coreutils-lang", rpm: "coreutils-lang~8.12~6.25.32.33.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "coreutils-x86", rpm: "coreutils-x86~8.12~6.25.32.33.1", rls: "SLES11.0SP3" ) )){
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
