if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.14151.1" );
	script_cve_id( "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:14151-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:14151-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-201914151-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kvm' package(s) announced via the SUSE-SU-2019:14151-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kvm fixes the following issues:

Security issues fixed:
CVE-2019-14378: Security fix for heap overflow in ip_reass on big packet
 input (bsc#1143794).

CVE-2019-12155: Security fix for null pointer dereference while
 releasing spice resources (bsc#1135902).

CVE-2019-13164: Security fix for qemu-bridge-helper ACL can be bypassed
 when names are too long (bsc#1140402)." );
	script_tag( name: "affected", value: "'kvm' package(s) on SUSE Linux Enterprise Server 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "kvm", rpm: "kvm~1.4.2~60.27.1", rls: "SLES11.0SP4" ) )){
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

