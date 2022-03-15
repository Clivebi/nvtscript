if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.841979" );
	script_version( "2020-11-12T09:08:42+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:08:42 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2014-09-24 06:03:20 +0200 (Wed, 24 Sep 2014)" );
	script_cve_id( "CVE-2014-5471", "CVE-2014-5472" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:N/I:N/A:C" );
	script_name( "Ubuntu Update for linux-ec2 USN-2355-1" );
	script_tag( name: "insight", value: "Chris Evans reported a flaw in the Linux
kernel's handling of iso9660 (compact disk filesystem) images. An attacker who
can mount a custom iso9660 image either via a CD/DVD drive or a loopback mount
could cause a denial of service (system crash or reboot). (CVE-2014-5471)

Chris Evans reported a flaw in the Linux kernel's handling of iso9660
(compact disk filesystem) images. An attacker who can mount a custom
iso9660 image, with a self-referential CL entry, either via a CD/DVD drive
or a loopback mount could cause a denial of service (unkillable mount
process). (CVE-2014-5472)" );
	script_tag( name: "affected", value: "linux-ec2 on Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "USN", value: "2355-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2355-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'linux-ec2'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "linux-image-2.6.32-370-ec2", ver: "2.6.32-370.86", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

