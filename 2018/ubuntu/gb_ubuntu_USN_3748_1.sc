if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843623" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-22 06:46:12 +0200 (Wed, 22 Aug 2018)" );
	script_cve_id( "CVE-2018-6557" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-11-21 18:15:00 +0000 (Wed, 21 Nov 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for base-files USN-3748-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'base-files'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Sander Bos discovered that the MOTD update script incorrectly handled
temporary files. A local attacker could use this issue to cause a denial of
service, or possibly escalate privileges if kernel symlink restrictions
were disabled." );
	script_tag( name: "affected", value: "base-files on Ubuntu 18.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3748-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3748-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU18\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "base-files", ver: "10.1ubuntu2.2", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

