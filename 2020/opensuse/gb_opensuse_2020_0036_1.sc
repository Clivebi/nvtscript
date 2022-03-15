if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852987" );
	script_version( "2021-08-13T09:00:57+0000" );
	script_cve_id( "CVE-2019-16779" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-13 09:00:57 +0000 (Fri, 13 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-14 01:15:00 +0000 (Tue, 14 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-14 04:01:31 +0000 (Tue, 14 Jan 2020)" );
	script_name( "openSUSE: Security Advisory for rubygem-excon (openSUSE-SU-2020:0036-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.1" );
	script_xref( name: "openSUSE-SU", value: "2020:0036-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00021.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-excon'
  package(s) announced via the openSUSE-SU-2020:0036-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rubygem-excon fixes the following issues:

  CVE-2019-16779 (boo#1159342): Fix a race condition around persistent
  connections, where a connection, which was interrupted, would leave data
  on the socket. Subsequent requests would then read this data, returning
  content from the previous response.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-36=1" );
	script_tag( name: "affected", value: "'rubygem-excon' package(s) on openSUSE Leap 15.1." );
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
if(release == "openSUSELeap15.1"){
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-rubygem-excon", rpm: "ruby2.5-rubygem-excon~0.59.0~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.5-rubygem-excon-doc", rpm: "ruby2.5-rubygem-excon-doc~0.59.0~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "uby2.5-rubygem-excon-testsuite", rpm: "uby2.5-rubygem-excon-testsuite~0.59.0~lp151.3.3.1", rls: "openSUSELeap15.1" ) )){
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

