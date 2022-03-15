if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852263" );
	script_version( "2021-09-07T12:01:40+0000" );
	script_cve_id( "CVE-2018-0886", "CVE-2018-1000852", "CVE-2018-8784", "CVE-2018-8785", "CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-07 12:01:40 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-13 13:45:00 +0000 (Wed, 13 Mar 2019)" );
	script_tag( name: "creation_date", value: "2019-01-30 04:03:58 +0100 (Wed, 30 Jan 2019)" );
	script_name( "openSUSE: Security Advisory for freerdp (openSUSE-SU-2019:0096-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:0096-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00046.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freerdp'
  package(s) announced via the openSUSE-SU-2019:0096-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for freerdp fixes the following issues:

  Security issues fixed:

  - CVE-2018-0886: Fix a remote code execution vulnerability (CredSSP)
  (bsc#1085416, bsc#1087240, bsc#1104918)

  - CVE-2018-8789: Fix several denial of service vulnerabilities in the in
  the NTLM Authentication module (bsc#1117965)

  - CVE-2018-8785: Fix a potential remote code execution vulnerability in
  the zgfx_decompress function (bsc#1117967)

  - CVE-2018-8786: Fix a potential remote code execution vulnerability in
  the update_read_bitmap_update function (bsc#1117966)

  - CVE-2018-8787: Fix a potential remote code execution vulnerability in
  the gdi_Bitmap_Decompress function (bsc#1117964)

  - CVE-2018-8788: Fix a potential remote code execution vulnerability in
  the nsc_rle_decode function (bsc#1117963)

  - CVE-2018-8784: Fix a potential remote code execution vulnerability in
  the zgfx_decompress_segment function (bsc#1116708)

  - CVE-2018-1000852: Fixed a remote memory access in the
  drdynvc_process_capability_request function (bsc#1120507)

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-96=1" );
	script_tag( name: "affected", value: "freerdp on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "freerdp", rpm: "freerdp~2.0.0~git.1463131968.4e66df7~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-debuginfo", rpm: "freerdp-debuginfo~2.0.0~git.1463131968.4e66df7~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-debugsource", rpm: "freerdp-debugsource~2.0.0~git.1463131968.4e66df7~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "freerdp-devel", rpm: "freerdp-devel~2.0.0~git.1463131968.4e66df7~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreerdp2", rpm: "libfreerdp2~2.0.0~git.1463131968.4e66df7~13.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libfreerdp2-debuginfo", rpm: "libfreerdp2-debuginfo~2.0.0~git.1463131968.4e66df7~13.1", rls: "openSUSELeap42.3" ) )){
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

