if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843855" );
	script_version( "2021-06-04T02:00:20+0000" );
	script_cve_id( "CVE-2018-8784", "CVE-2018-8785", "CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-04 02:00:20 +0000 (Fri, 04 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 19:12:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-12-13 07:30:11 +0100 (Thu, 13 Dec 2018)" );
	script_name( "Ubuntu Update for freerdp2 USN-3845-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU14\\.04 LTS" );
	script_xref( name: "USN", value: "3845-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3845-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freerdp2'
  package(s) announced via the USN-3845-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Eyal Itkin discovered FreeRDP incorrectly handled certain stream
encodings.  A malicious server could use this issue to cause
FreeRDP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applies to Ubuntu 18.04
LTS and Ubuntu 18.10. (CVE-2018-8784, CVE-2018-8785)

Eyal Itkin discovered FreeRDP incorrectly handled bitmaps.  A
malicious server could use this issue to cause FreeRDP to crash,
resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2018-8786, CVE-2018-8787)

Eyal Itkin discovered FreeRDP incorrectly handled certain stream
encodings.  A malicious server could use this issue to cause
FreeRDP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applies to Ubuntu 16.04
LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8788)

Eyal Itkin discovered FreeRDP incorrectly handled NTLM
authentication.  A malicious server could use this issue to cause
FreeRDP to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only applies to Ubuntu 16.04
LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8789)" );
	script_tag( name: "affected", value: "freerdp2 on Ubuntu 18.10,
  Ubuntu 18.04 LTS,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS." );
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
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libfreerdp1", ver: "1.0.2-2ubuntu1.2", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

