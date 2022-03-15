if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842033" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-12 06:24:41 +0100 (Wed, 12 Nov 2014)" );
	script_cve_id( "CVE-2014-3641", "CVE-2014-7230" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_name( "Ubuntu Update for cinder USN-2405-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'cinder'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Duncan Thomas discovered that OpenStack
Cinder did not properly track the file format when using the GlusterFS of Smbfs
drivers. A remote authenticated user could exploit this to potentially obtain file
contents from the compute host. (CVE-2014-3641)

Amrith Kumar discovered that OpenStack Cinder did not properly sanitize log
message contents. Under certain circumstances, a local attacker with read
access to Cinder log files could obtain access to sensitive information.
(CVE-2014-7230)" );
	script_tag( name: "affected", value: "cinder on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2405-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2405-1/" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "python-cinder", ver: "1:2014.1.3-0ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

