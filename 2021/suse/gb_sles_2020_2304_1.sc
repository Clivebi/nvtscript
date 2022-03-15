if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.2304.1" );
	script_cve_id( "CVE-2020-15705" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:2304-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:2304-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20202304-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'grub2' package(s) announced via the SUSE-SU-2020:2304-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for grub2 fixes the following issues:

CVE-2020-15705: Fail kernel validation without shim protocol
 (bsc#1174421).

Add fibre channel device's ofpath support to grub-ofpathname and search
 hint to speed up root device discovery (bsc#1172745)." );
	script_tag( name: "affected", value: "'grub2' package(s) on HPE Helion Openstack 8, SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "grub2", rpm: "grub2~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-arm64-efi", rpm: "grub2-arm64-efi~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-debuginfo", rpm: "grub2-debuginfo~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-debugsource", rpm: "grub2-debugsource~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-i386-pc", rpm: "grub2-i386-pc~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-powerpc-ieee1275", rpm: "grub2-powerpc-ieee1275~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-s390x-emu", rpm: "grub2-s390x-emu~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-snapper-plugin", rpm: "grub2-snapper-plugin~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-systemd-sleep-plugin", rpm: "grub2-systemd-sleep-plugin~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-efi", rpm: "grub2-x86_64-efi~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-xen", rpm: "grub2-x86_64-xen~2.02~4.61.1", rls: "SLES12.0SP3" ) )){
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

