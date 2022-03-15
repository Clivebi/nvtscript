if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842717" );
	script_version( "2021-09-17T14:48:43+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 14:48:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-04-19 05:18:12 +0200 (Tue, 19 Apr 2016)" );
	script_cve_id( "CVE-2015-7801", "CVE-2015-7802", "CVE-2016-2191", "CVE-2016-3981", "CVE-2016-3982" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for optipng USN-2951-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'optipng'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Gustavo Grieco discovered that OptiPNG
  incorrectly handled memory. A remote attacker could use this issue with a
  specially crafted image file to cause OptiPNG to crash, resulting in a denial
  of service. (CVE-2015-7801)

  Gustavo Grieco discovered that OptiPNG incorrectly handled memory. A remote
  attacker could use this issue with a specially crafted image file to cause
  OptiPNG to crash, resulting in a denial of service. (CVE-2015-7802)

  Hans Jerry Illikainen discovered that OptiPNG incorrectly handled memory. A
  remote attacker could use this issue with a specially crafted image file to
  cause OptiPNG to crash, resulting in a denial of service, or possibly
  execute arbitrary code. (CVE-2016-2191)

  Henri Salo discovered that OptiPNG incorrectly handled memory. A remote
  attacker could use this issue with a specially crafted image file to cause
  OptiPNG to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-3981)

  Henri Salo discovered that OptiPNG incorrectly handled memory. A remote
  attacker could use this issue with a specially crafted image file to cause
  OptiPNG to crash, resulting in a denial of service, or possibly execute
  arbitrary code. (CVE-2016-3982)" );
	script_tag( name: "affected", value: "optipng on Ubuntu 15.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2951-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2951-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|12\\.04 LTS|15\\.10)" );
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
	if(( res = isdpkgvuln( pkg: "optipng", ver: "0.6.4-1ubuntu0.14.04.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "optipng", ver: "0.6.4-1ubuntu0.12.04.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "optipng", ver: "0.7.5-1ubuntu0.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

