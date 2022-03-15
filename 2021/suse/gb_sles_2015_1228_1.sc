if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.1228.1" );
	script_cve_id( "CVE-2014-2891", "CVE-2015-4171" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-13 21:47:00 +0000 (Mon, 13 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:1228-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:1228-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20151228-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'strongswan' package(s) announced via the SUSE-SU-2015:1228-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "strongswan was updated to fix two security issues:
An issue that could enable rogue servers to gain user credentials from a client in certain IKEv2 setups. (CVE-2015-4171)
A bug in decoding ID_DER_ASN1_DN ID payloads that could be used for remote denial of service attacks. (CVE-2014-2891)
Security Issues:
CVE-2015-4171 CVE-2014-2891" );
	script_tag( name: "affected", value: "'strongswan' package(s) on SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "strongswan", rpm: "strongswan~4.4.0~6.19.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "strongswan-doc", rpm: "strongswan-doc~4.4.0~6.19.1", rls: "SLES10.0SP4" ) )){
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

