if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2995.1" );
	script_cve_id( "CVE-2021-3712" );
	script_tag( name: "creation_date", value: "2021-09-10 02:20:59 +0000 (Fri, 10 Sep 2021)" );
	script_version( "2021-09-10T02:20:59+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 02:20:59 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-31 16:48:00 +0000 (Tue, 31 Aug 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2995-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2995-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212995-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl-1_0_0' package(s) announced via the SUSE-SU-2021:2995-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl-1_0_0 fixes the following issues:

CVE-2021-3712: This is an update for the incomplete fix for
 CVE-2021-3712. Read buffer overruns processing ASN.1 strings
 (bsc#1189521)." );
	script_tag( name: "affected", value: "'openssl-1_0_0' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9." );
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_0_0-devel", rpm: "libopenssl-1_0_0-devel~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-32bit", rpm: "libopenssl1_0_0-32bit~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo-32bit", rpm: "libopenssl1_0_0-debuginfo-32bit~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-hmac", rpm: "libopenssl1_0_0-hmac~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-hmac-32bit", rpm: "libopenssl1_0_0-hmac-32bit~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0", rpm: "openssl-1_0_0~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debuginfo", rpm: "openssl-1_0_0-debuginfo~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debugsource", rpm: "openssl-1_0_0-debugsource~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-doc", rpm: "openssl-1_0_0-doc~1.0.2p~3.42.2", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_0_0-devel", rpm: "libopenssl-1_0_0-devel~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-32bit", rpm: "libopenssl1_0_0-32bit~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo-32bit", rpm: "libopenssl1_0_0-debuginfo-32bit~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-hmac", rpm: "libopenssl1_0_0-hmac~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-hmac-32bit", rpm: "libopenssl1_0_0-hmac-32bit~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0", rpm: "openssl-1_0_0~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debuginfo", rpm: "openssl-1_0_0-debuginfo~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debugsource", rpm: "openssl-1_0_0-debugsource~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-doc", rpm: "openssl-1_0_0-doc~1.0.2p~3.42.2", rls: "SLES12.0SP5" ) )){
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

