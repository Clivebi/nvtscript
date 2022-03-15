if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842962" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-11-29 05:39:51 +0100 (Tue, 29 Nov 2016)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for gst-plugins-good1.0 USN-3135-2" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gst-plugins-good1.0'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "USN-3135-1 fixed a vulnerability in GStreamer
  Good Plugins. The original security fix was incomplete. This update fixes the problem.

Original advisory details:

Chris Evans discovered that GStreamer Good Plugins did not correctly handle
malformed FLC movie files. If a user were tricked into opening a crafted
FLC movie file with a GStreamer application, an attacker could cause a
denial of service via application crash, or execute arbitrary code with the
privileges of the user invoking the program." );
	script_tag( name: "affected", value: "gst-plugins-good1.0 on Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 16.10,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3135-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3135-2/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|16\\.04 LTS|16\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good:i386", ver: "0.10.31-3+nmu1ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good:amd64", ver: "0.10.31-3+nmu1ubuntu5.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:i386", ver: "1.2.4-1~ubuntu1.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:amd64", ver: "1.2.4-1~ubuntu1.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good:i386", ver: "0.10.31-1ubuntu1.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gstreamer0.10-plugins-good:amd64", ver: "0.10.31-1ubuntu1.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:i386", ver: "1.8.2-1ubuntu0.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:amd64", ver: "1.8.2-1ubuntu0.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:i386", ver: "1.8.3-1ubuntu1.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "gstreamer1.0-plugins-good:amd64", ver: "1.8.3-1ubuntu1.2", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

