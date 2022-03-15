if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853681" );
	script_version( "2021-08-26T11:01:06+0000" );
	script_cve_id( "CVE-2020-12362", "CVE-2020-12363", "CVE-2020-12364", "CVE-2020-12373" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-26 11:01:06 +0000 (Thu, 26 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-22 18:07:00 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:59:51 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for kernel-firmware (openSUSE-SU-2021:0407-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0407-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KH2XS5MRKRSCX3I5AS4LGZH576PO6KUD" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'kernel-firmware'
  package(s) announced via the openSUSE-SU-2021:0407-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for kernel-firmware fixes the following issues:

  - CVE-2020-12373: Fixed an expired pointer dereference may lead to DOS
       (bsc#1181738).

  - CVE-2020-12364: Fixed a null pointer reference may lead to DOS
       (bsc#1181736).

  - CVE-2020-12362: Fixed an integer overflow which could have led to
       privilege escalation (bsc#1181720).

  - CVE-2020-12363: Fixed an improper input validation which may have led to
       DOS (bsc#1181735).

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'kernel-firmware' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "kernel-firmware", rpm: "kernel-firmware~20200107~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ucode-amd", rpm: "ucode-amd~20200107~lp152.2.6.1", rls: "openSUSELeap15.2" ) )){
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

