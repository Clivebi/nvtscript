if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851151" );
	script_version( "2020-01-31T07:58:03+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 07:58:03 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2015-12-31 05:12:48 +0100 (Thu, 31 Dec 2015)" );
	script_cve_id( "CVE-2015-8370" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "SUSE: Security Advisory for grub2 (SUSE-SU-2015:2399-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'grub2'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for grub2 provides the following fixes and enhancements:

  Security issue fixed:

  - Fix buffer overflows when reading username and password. (bsc#956631,
  CVE-2015-8370)

  Non security issues fixed:

  - Expand list of grub.cfg search path in PV Xen guests for systems
  installed
  on btrfs snapshots. (bsc#946148, bsc#952539)

  - Add --image switch to force zipl update to specific kernel. (bsc#928131)

  - Do not use shim lock protocol for reading PE header as it won't be
  available when secure boot is disabled. (bsc#943380)

  - Make firmware flaw condition be more precisely detected and add debug
  message for the case." );
	script_tag( name: "affected", value: "grub2 on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "SUSE-SU", value: "2015:2399-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=(SLED12\\.0SP0|SLES12\\.0SP0)" );
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
if(release == "SLED12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "grub2", rpm: "grub2~2.02~beta2~56.9.4", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-debuginfo", rpm: "grub2-debuginfo~2.02~beta2~56.9.4", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-i386-pc", rpm: "grub2-i386-pc~2.02~beta2~56.9.4", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-efi", rpm: "grub2-x86_64-efi~2.02~beta2~56.9.4", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-xen", rpm: "grub2-x86_64-xen~2.02~beta2~56.9.4", rls: "SLED12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-snapper-plugin", rpm: "grub2-snapper-plugin~2.02~beta2~56.9.4", rls: "SLED12.0SP0" ) )){
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
if(release == "SLES12.0SP0"){
	if(!isnull( res = isrpmvuln( pkg: "grub2", rpm: "grub2~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-debuginfo", rpm: "grub2-debuginfo~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-powerpc-ieee1275", rpm: "grub2-powerpc-ieee1275~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-i386-pc", rpm: "grub2-i386-pc~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-efi", rpm: "grub2-x86_64-efi~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-x86_64-xen", rpm: "grub2-x86_64-xen~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-snapper-plugin", rpm: "grub2-snapper-plugin~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-debugsource", rpm: "grub2-debugsource~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "grub2-s390x-emu", rpm: "grub2-s390x-emu~2.02~beta2~56.9.4", rls: "SLES12.0SP0" ) )){
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

