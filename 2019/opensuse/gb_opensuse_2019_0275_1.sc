if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852328" );
	script_version( "2021-09-07T10:01:34+0000" );
	script_cve_id( "CVE-2018-5383" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-07 10:01:34 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-03-02 04:08:06 +0100 (Sat, 02 Mar 2019)" );
	script_name( "openSUSE: Security Advisory for kernel-firmware (openSUSE-SU-2019:0275-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:0275-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00001.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-firmware'
  package(s) announced via the openSUSE-SU-2019:0275-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kernel-firmware fixes the following issues:

  Security issue fixed:

  - CVE-2018-5383: Fixed an implementation issue in Bluetooth where the
  elliptic curve parameters were not sufficiently validated during
  Diffie-Hellman key exchange (bsc#1104301).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-275=1" );
	script_tag( name: "affected", value: "kernel-firmware on openSUSE Leap 42.3." );
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
	if(!isnull( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~20170530~26.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ucode-amd", rpm: "ucode-amd~20170530~26.1", rls: "openSUSELeap42.3" ) )){
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

