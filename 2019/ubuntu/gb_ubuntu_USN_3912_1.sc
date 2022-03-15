if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843937" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2017-12447" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-21 15:59:00 +0000 (Thu, 21 Mar 2019)" );
	script_tag( name: "creation_date", value: "2019-03-21 09:50:58 +0100 (Thu, 21 Mar 2019)" );
	script_name( "Ubuntu Update for gdk-pixbuf USN-3912-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU16\\.04 LTS" );
	script_xref( name: "USN", value: "3912-1" );
	script_xref( name: "URL", value: "https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-March/004807.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gdk-pixbuf'
  package(s) announced via the USN-3912-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the GDK-PixBuf library did not properly handle
certain BMP images. If an user or automated system were tricked into
opening a specially crafted BMP file, a remote attacker could use this flaw
to cause GDK-PixBuf to crash, resulting in a denial of service, or possibly
execute arbitrary code." );
	script_tag( name: "affected", value: "gdk-pixbuf on Ubuntu 16.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libgdk-pixbuf2.0-0", ver: "2.32.2-1ubuntu1.6", rls: "UBUNTU16.04 LTS", remove_arch: TRUE ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

