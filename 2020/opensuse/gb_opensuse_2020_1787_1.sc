if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853543" );
	script_version( "2021-08-13T14:00:52+0000" );
	script_cve_id( "CVE-2019-13314" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 14:00:52 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-07 01:15:00 +0000 (Sat, 07 Nov 2020)" );
	script_tag( name: "creation_date", value: "2020-11-03 04:01:28 +0000 (Tue, 03 Nov 2020)" );
	script_name( "openSUSE: Security Advisory for virt-bootstrap (openSUSE-SU-2020:1787-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "openSUSE-SU", value: "2020:1787-1" );
	script_xref( name: "URL", value: "http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00080.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'virt-bootstrap'
  package(s) announced via the openSUSE-SU-2020:1787-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for virt-bootstrap fixes the following issues:

  Security issue fixed:

  - CVE-2019-13314: Allow providing the container's root password using a
  file (bsc#1140750).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1787=1" );
	script_tag( name: "affected", value: "'virt-bootstrap' package(s) on openSUSE Leap 15.2." );
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
	if(!isnull( res = isrpmvuln( pkg: "python2-virt-bootstrap", rpm: "python2-virt-bootstrap~1.0.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python3-virt-bootstrap", rpm: "python3-virt-bootstrap~1.0.0~lp152.5.3.1", rls: "openSUSELeap15.2" ) )){
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

