if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.14807.1" );
	script_cve_id( "CVE-2021-22946", "CVE-2021-22947" );
	script_tag( name: "creation_date", value: "2021-09-24 07:14:32 +0000 (Fri, 24 Sep 2021)" );
	script_version( "2021-09-24T07:14:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-24 07:14:32 +0000 (Fri, 24 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-09-24 07:13:58 +0000 (Fri, 24 Sep 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:14807-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:14807-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-202114807-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2021:14807-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for curl fixes the following issues:

CVE-2021-22947: Fixed STARTTLS protocol injection via MITM (bsc#1190374).

CVE-2021-22946: Fixed protocol downgrade required TLS bypassed
 (bsc#1190373)." );
	script_tag( name: "affected", value: "'curl' package(s) on SUSE Linux Enterprise Server 11." );
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
if(release == "SLES11.0"){
	if(!isnull( res = isrpmvuln( pkg: "curl-openssl1", rpm: "curl-openssl1~7.37.0~70.74.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-openssl1-32bit", rpm: "libcurl4-openssl1-32bit~7.37.0~70.74.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-openssl1", rpm: "libcurl4-openssl1~7.37.0~70.74.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libcurl4-openssl1-x86", rpm: "libcurl4-openssl1-x86~7.37.0~70.74.1", rls: "SLES11.0" ) )){
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

