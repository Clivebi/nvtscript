if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842599" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-01-13 06:14:18 +0100 (Wed, 13 Jan 2016)" );
	script_cve_id( "CVE-2011-4600", "CVE-2014-8136", "CVE-2015-0236", "CVE-2015-5247", "CVE-2015-5313" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libvirt USN-2867-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libvirt'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that libvirt incorrectly
  handled the firewall rules on bridge networks when the daemon was restarted.
  This could result in an unintended firewall configuration. This issue only
  applied to Ubuntu 12.04 LTS. (CVE-2011-4600)

  Peter Krempa discovered that libvirt incorrectly handled locking when
  certain ACL checks failed. A local attacker could use this issue to cause
  libvirt to stop responding, resulting in a denial of service. This issue
  only applied to Ubuntu 14.04 LTS. (CVE-2014-8136)

  Luyao Huang discovered that libvirt incorrectly handled VNC passwords in
  shapshot and image files. A remote authenticated user could use this issue
  to possibly obtain VNC passwords. This issue only affected Ubuntu 14.04
  LTS. (CVE-2015-0236)

  Han Han discovered that libvirt incorrectly handled volume creation
  failure when used with NFS. A remote authenticated user could use this
  issue to cause libvirt to crash, resulting in a denial of service. This
  issue only applied to Ubuntu 15.10. (CVE-2015-5247)

  Ossi Herrala and Joonas Kuorilehto discovered that libvirt incorrectly
  performed storage pool name validation. A remote authenticated user could
  use this issue to bypass ACLs and gain access to unintended files. This
  issue only applied to Ubuntu 14.04 LTS, Ubuntu 15.04 and Ubuntu 15.10.
  (CVE-2015-5313)" );
	script_tag( name: "affected", value: "libvirt on Ubuntu 15.10,
  Ubuntu 15.04,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2867-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2867-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.2.12-0ubuntu14.4", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "1.2.12-0ubuntu14.4", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.2.2-0ubuntu13.1.16", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "1.2.2-0ubuntu13.1.16", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "0.9.8-2ubuntu17.23", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "0.9.8-2ubuntu17.23", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "libvirt-bin", ver: "1.2.16-2ubuntu11.15.10.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libvirt0", ver: "1.2.16-2ubuntu11.15.10.2", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

