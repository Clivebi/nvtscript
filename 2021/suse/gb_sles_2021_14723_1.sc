if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.14723.1" );
	script_cve_id( "CVE-2018-7544", "CVE-2020-15078" );
	script_tag( name: "creation_date", value: "2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-04-10 15:15:00 +0000 (Tue, 10 Apr 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:14723-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:14723-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-202114723-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openvpn-openssl1' package(s) announced via the SUSE-SU-2021:14723-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openvpn-openssl1 fixes the following issues:

CVE-2020-15078: Fixed authentication bypass with deferred authentication
 (bsc#1185279).

CVE-2018-7544: Fixed cross-protocol scripting issue that was discovered
 in the management interface (bsc#1085803)." );
	script_tag( name: "affected", value: "'openvpn-openssl1' package(s) on SUSE Linux Enterprise Server 11." );
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
	if(!isnull( res = isrpmvuln( pkg: "openvpn-openssl1", rpm: "openvpn-openssl1~2.3.2~0.10.9.1", rls: "SLES11.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openvpn-openssl1-down-root-plugin", rpm: "openvpn-openssl1-down-root-plugin~2.3.2~0.10.9.1", rls: "SLES11.0" ) )){
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

