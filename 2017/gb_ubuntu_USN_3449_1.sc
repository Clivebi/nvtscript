if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843332" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-10-12 10:26:14 +0200 (Thu, 12 Oct 2017)" );
	script_cve_id( "CVE-2015-3241", "CVE-2015-3280", "CVE-2015-5162", "CVE-2015-7548", "CVE-2015-7713", "CVE-2015-8749", "CVE-2016-2140" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for nova USN-3449-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'nova'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "George Shuklin discovered that OpenStack
  Nova incorrectly handled the migration process. A remote authenticated user
  could use this issue to consume resources, resulting in a denial of service.
  (CVE-2015-3241) George Shuklin and Tushar Patil discovered that OpenStack Nova
  incorrectly handled deleting instances. A remote authenticated user could use
  this issue to consume disk resources, resulting in a denial of service.
  (CVE-2015-3280) It was discovered that OpenStack Nova incorrectly limited
  qemu-img calls. A remote authenticated user could use this issue to consume
  resources, resulting in a denial of service. (CVE-2015-5162) Matthew Booth
  discovered that OpenStack Nova incorrectly handled snapshots. A remote
  authenticated user could use this issue to read arbitrary files. (CVE-2015-7548)
  Sreekumar S. and Suntao discovered that OpenStack Nova incorrectly applied
  security group changes. A remote attacker could possibly use this issue to
  bypass intended restriction changes by leveraging an instance that was running
  when the change was made. (CVE-2015-7713) Matt Riedemann discovered that
  OpenStack Nova incorrectly handled logging. A local attacker could possibly use
  this issue to obtain sensitive information from log files. (CVE-2015-8749)
  Matthew Booth discovered that OpenStack Nova incorrectly handled certain qcow2
  headers. A remote authenticated user could possibly use this issue to read
  arbitrary files. (CVE-2016-2140)" );
	script_tag( name: "affected", value: "nova on Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3449-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3449-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "python-nova", ver: "1:2014.1.5-0ubuntu1.7", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

