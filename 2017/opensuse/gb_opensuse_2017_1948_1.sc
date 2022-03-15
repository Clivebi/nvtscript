if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851584" );
	script_version( "2021-09-15T12:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-15 12:01:38 +0000 (Wed, 15 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-25 07:25:13 +0200 (Tue, 25 Jul 2017)" );
	script_cve_id( "CVE-2017-2295" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-24 13:36:00 +0000 (Thu, 24 May 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for rubygem-puppet (openSUSE-SU-2017:1948-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rubygem-puppet'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for rubygem-puppet fixes the following issues:

  - CVE-2017-2295: A remote attacker could have forced unsafe YAML
  deserialization which could have led to code execution (bsc#1040151)" );
	script_tag( name: "affected", value: "rubygem-puppet on openSUSE Leap 42.2" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2017:1948-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.2" );
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
if(release == "openSUSELeap42.2"){
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-puppet", rpm: "ruby2.1-rubygem-puppet~3.8.7~17.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-puppet-doc", rpm: "ruby2.1-rubygem-puppet-doc~3.8.7~17.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby2.1-rubygem-puppet-testsuite", rpm: "ruby2.1-rubygem-puppet-testsuite~3.8.7~17.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-puppet", rpm: "rubygem-puppet~3.8.7~17.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-puppet-master", rpm: "rubygem-puppet-master~3.8.7~17.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-puppet-emacs", rpm: "rubygem-puppet-emacs~3.8.7~17.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-puppet-master-unicorn", rpm: "rubygem-puppet-master-unicorn~3.8.7~17.3.1", rls: "openSUSELeap42.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-puppet-vim", rpm: "rubygem-puppet-vim~3.8.7~17.3.1", rls: "openSUSELeap42.2" ) )){
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

