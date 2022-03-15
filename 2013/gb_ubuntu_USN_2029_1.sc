if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841621" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-11-18 16:00:35 +0530 (Mon, 18 Nov 2013)" );
	script_cve_id( "CVE-2013-2186" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Ubuntu Update for libcommons-fileupload-java USN-2029-1" );
	script_tag( name: "affected", value: "libcommons-fileupload-java on Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that Apache Commons FileUpload incorrectly
handled file names with NULL bytes in serialized instances. An attacker could
use this issue to possibly write to arbitrary files." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2029-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2029-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libcommons-fileupload-java'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libcommons-fileupload-java", ver: "1.2.1-3ubuntu2.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

