if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843621" );
	script_version( "2021-06-03T02:00:18+0000" );
	script_tag( name: "last_modification", value: "2021-06-03 02:00:18 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-21 06:44:51 +0200 (Tue, 21 Aug 2018)" );
	script_cve_id( "CVE-2018-0501" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-17 18:49:00 +0000 (Thu, 17 Jan 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for apt USN-3746-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that APT incorrectly handled
the mirror method (<A HREF='mirror://'>mirror://</A>). If a remote attacker were
able to perform a man-in-the-middle attack, this flaw could potentially be used
to install altered packages in environments configured to use
<A HREF='mirror://'>mirror://</A> entries." );
	script_tag( name: "affected", value: "apt on Ubuntu 18.04 LTS" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "USN", value: "3746-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3746-1/" );
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
	if(( res = isdpkgvuln( pkg: "apt", ver: "1.6.3ubuntu0.1", rls: "UBUNTU18.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

