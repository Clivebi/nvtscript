if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1295.1" );
	script_cve_id( "CVE-2017-5715", "CVE-2018-1064", "CVE-2018-5748" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:44 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-20 01:29:00 +0000 (Wed, 20 Jun 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1295-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1295-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181295-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt' package(s) announced via the SUSE-SU-2018:1295-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for libvirt fixes the following issues:
Security issues fixed:
- CVE-2017-5715: Spectre fixes for libvirt (bsc#1079869, bsc#1088147,
 bsc#1087887).
- CVE-2018-1064: Avoid denial of service reading from QEMU guest agent
 (bsc#1083625).
- CVE-2018-5748: Avoid denial of service reading from QEMU monitor
 (bsc#1076500).
Bug fixes:
- bsc#1025340: Use xend for nodeGetFreeMemory API.
- bsc#960742: Allow read access to script directories in libvirtd AppArmor
 profile.
- bsc#936233: Introduce qemuDomainDefCheckABIStability." );
	script_tag( name: "affected", value: "'libvirt' package(s) on SUSE Linux Enterprise Debuginfo 11-SP3, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Server 11-SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libvirt", rpm: "libvirt~1.0.5.9~21.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client", rpm: "libvirt-client~1.0.5.9~21.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-client-32bit", rpm: "libvirt-client-32bit~1.0.5.9~21.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-doc", rpm: "libvirt-doc~1.0.5.9~21.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-lock-sanlock", rpm: "libvirt-lock-sanlock~1.0.5.9~21.5.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libvirt-python", rpm: "libvirt-python~1.0.5.9~21.5.1", rls: "SLES11.0SP3" ) )){
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

