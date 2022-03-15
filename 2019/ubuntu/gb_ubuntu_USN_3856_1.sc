if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843869" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2018-10910" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:33:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-01-15 04:00:44 +0100 (Tue, 15 Jan 2019)" );
	script_name( "Ubuntu Update for gnome-bluetooth USN-3856-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(18\\.04 LTS)" );
	script_xref( name: "USN", value: "3856-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3856-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'gnome-bluetooth' package(s) announced via the USN-3856-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "insight", value: "Chris Marchesi discovered that BlueZ
  incorrectly handled disabling Bluetooth visibility. A remote attacker could
  possibly pair to devices, contrary to expectations. This update adds a workaround
  to GNOME Bluetooth to fix the issue." );
	script_tag( name: "affected", value: "gnome-bluetooth on Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(( res = isdpkgvuln( pkg: "gnome-bluetooth", ver: "3.28.0-2ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libgnome-bluetooth13", ver: "3.28.0-2ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

