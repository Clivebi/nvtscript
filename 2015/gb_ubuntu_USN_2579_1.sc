if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842178" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-28 05:16:57 +0200 (Tue, 28 Apr 2015)" );
	script_cve_id( "CVE-2014-8169" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for autofs USN-2579-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'autofs'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that autofs incorrectly
filtered environment variables when using program maps. When program maps were
configured, a local user could use this issue to escalate privileges.

This update changes the default behaviour by adding a prefix to environment
variables. Sites using program maps will need to adapt to the new variable
names, or revert to the previous names by using a new configuration option
called FORCE_STANDARD_PROGRAM_MAP_ENV." );
	script_tag( name: "affected", value: "autofs on Ubuntu 14.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2579-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2579-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.10" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "autofs", ver: "5.0.8-1ubuntu1.1", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

