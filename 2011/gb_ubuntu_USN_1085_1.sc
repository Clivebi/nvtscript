if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1085-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840610" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-15 14:58:18 +0100 (Tue, 15 Mar 2011)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1085-1" );
	script_cve_id( "CVE-2010-2482", "CVE-2010-2483", "CVE-2010-2595", "CVE-2010-2597", "CVE-2010-2598", "CVE-2010-2630", "CVE-2010-3087", "CVE-2011-0191", "CVE-2011-0192" );
	script_name( "Ubuntu Update for tiff vulnerabilities USN-1085-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(9\\.10|6\\.06 LTS|10\\.04 LTS|8\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1085-1" );
	script_tag( name: "affected", value: "tiff vulnerabilities on Ubuntu 6.06 LTS,
  Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Sauli Pahlman discovered that the TIFF library incorrectly handled invalid
  td_stripbytecount fields. If a user or automated system were tricked into
  opening a specially crafted TIFF image, a remote attacker could crash the
  application, leading to a denial of service. This issue only affected
  Ubuntu 10.04 LTS and 10.10. (CVE-2010-2482)

  Sauli Pahlman discovered that the TIFF library incorrectly handled TIFF
  files with an invalid combination of SamplesPerPixel and Photometric
  values. If a user or automated system were tricked into opening a specially
  crafted TIFF image, a remote attacker could crash the application, leading
  to a denial of service. This issue only affected Ubuntu 10.10.
  (CVE-2010-2482)

  Nicolae Ghimbovschi discovered that the TIFF library incorrectly handled
  invalid ReferenceBlackWhite values. If a user or automated system were
  tricked into opening a specially crafted TIFF image, a remote attacker
  could crash the application, leading to a denial of service.
  (CVE-2010-2595)

  Sauli Pahlman discovered that the TIFF library incorrectly handled certain
  default fields. If a user or automated system were tricked into opening a
  specially crafted TIFF image, a remote attacker could crash the
  application, leading to a denial of service. (CVE-2010-2597, CVE-2010-2598)

  It was discovered that the TIFF library incorrectly validated certain
  data types. If a user or automated system were tricked into opening a
  specially crafted TIFF image, a remote attacker could crash the
  application, leading to a denial of service. (CVE-2010-2630)

  It was discovered that the TIFF library incorrectly handled downsampled
  JPEG data. If a user or automated system were tricked into opening a
  specially crafted TIFF image, a remote attacker could execute arbitrary
  code with user privileges, or crash the application, leading to a denial of
  service. This issue only affected Ubuntu 10.04 LTS and 10.10.
  (CVE-2010-3087)

  It was discovered that the TIFF library incorrectly handled certain JPEG
  data. If a user or automated system were tricked into opening a specially
  crafted TIFF image, a remote attacker could execute arbitrary code with
  user privileges, or crash the application, leading to a denial of service.
  This issue only affected Ubuntu 6.06 LTS, 8.04 LTS and 9.10.
  (CVE-2011-0191)

  It was discovered that the TIFF library incorrectly handled certain TIFF
  FAX images. If a user or automated system were tricked into opening a
  specially crafted TIFF FAX image, a remote attacker could execute arbitrary
  code with user privileges, or crash the application, leading to a denial of
  service. (CVE-2011-0191)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "3.8.2-13ubuntu0.4", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.8.2-13ubuntu0.4", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4", ver: "3.8.2-13ubuntu0.4", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.8.2-13ubuntu0.4", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "3.8.2-13ubuntu0.4", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff-doc", ver: "3.8.2-13ubuntu0.4", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU6.06 LTS"){
	if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "3.7.4-1ubuntu3.9", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.7.4-1ubuntu3.9", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4", ver: "3.7.4-1ubuntu3.9", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.7.4-1ubuntu3.9", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "3.7.4-1ubuntu3.9", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "3.9.2-2ubuntu0.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.9.2-2ubuntu0.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4", ver: "3.9.2-2ubuntu0.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.9.2-2ubuntu0.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "3.9.2-2ubuntu0.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff-doc", ver: "3.9.2-2ubuntu0.4", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "3.8.2-7ubuntu3.7", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.8.2-7ubuntu3.7", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4", ver: "3.8.2-7ubuntu3.7", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.8.2-7ubuntu3.7", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "3.8.2-7ubuntu3.7", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "libtiff-tools", ver: "3.9.4-2ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4-dev", ver: "3.9.4-2ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff4", ver: "3.9.4-2ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiffxx0c2", ver: "3.9.4-2ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff-opengl", ver: "3.9.4-2ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libtiff-doc", ver: "3.9.4-2ubuntu0.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

