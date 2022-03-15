if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851192" );
	script_version( "2020-01-31T08:23:39+0000" );
	script_tag( name: "last_modification", value: "2020-01-31 08:23:39 +0000 (Fri, 31 Jan 2020)" );
	script_tag( name: "creation_date", value: "2016-02-02 17:17:38 +0100 (Tue, 02 Feb 2016)" );
	script_cve_id( "CVE-2015-8770" );
	script_tag( name: "cvss_base", value: "6.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for roundcubemail (openSUSE-SU-2016:0213-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'roundcubemail'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update to roundcubemail 1.1.4 fixes the following issues:

  - CVE-2015-8770: Path traversal vulnerability allowed code execution to
  remote authenticated users if they were also upload files to the same
  server through some other method (boo#962067)

  This update also contains all upstream fixes in 1.1.4. The package was
  updated to use generic PHP requirements for use with other prefixes than
  'php5-'" );
	script_tag( name: "affected", value: "roundcubemail on openSUSE Leap 42.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:0213-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.1" );
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
if(release == "openSUSELeap42.1"){
	if(!isnull( res = isrpmvuln( pkg: "roundcubemail", rpm: "roundcubemail~1.1.4~6.1", rls: "openSUSELeap42.1" ) )){
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

