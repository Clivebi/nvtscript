if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842402" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-08-06 07:02:07 +0200 (Thu, 06 Aug 2015)" );
	script_cve_id( "CVE-2014-7144", "CVE-2015-1852" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for python-keystoneclient USN-2705-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-keystoneclient'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Qin Zhao discovered Keystone disabled
certification verification when the 'insecure' option is set in a paste
configuration (paste.ini) file regardless of the value, which allows remote
attackers to conduct man-in-the-middle attacks via a crafted certificate.
(CVE-2014-7144)

Brant Knudson discovered Keystone disabled certification verification when
the 'insecure' option is set in a paste configuration (paste.ini)
file regardless of the value, which allows remote attackers to conduct
man-in-the-middle attacks via a crafted certificate. (CVE-2015-1852)" );
	script_tag( name: "affected", value: "python-keystoneclient on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2705-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2705-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "python-keystoneclient", ver: "1:0.7.1-ubuntu1.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

