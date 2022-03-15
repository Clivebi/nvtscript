if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.844025" );
	script_version( "2021-08-31T12:01:27+0000" );
	script_cve_id( "CVE-2018-8784", "CVE-2018-8785", "CVE-2018-8786", "CVE-2018-8787", "CVE-2018-8788", "CVE-2018-8789" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 12:01:27 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 19:12:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-05-29 02:00:29 +0000 (Wed, 29 May 2019)" );
	script_name( "Ubuntu Update for freerdp USN-3845-2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU18\\.10)" );
	script_xref( name: "USN", value: "3845-2" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3845-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freerdp'
  package(s) announced via the USN-3845-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "USN-3845-1 fixed several vulnerabilities in FreeRDP. This update
provides the
corresponding update for Ubuntu 18.04 LTS and Ubuntu 18.10.

Original advisory details:

Eyal Itkin discovered FreeRDP incorrectly handled certain stream
encodings.  A
malicious server could use this issue to cause FreeRDP to crash,
resulting in a
denial of service, or possibly execute arbitrary code. This issue only
applies
to Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-8784, CVE-2018-8785)

Eyal Itkin discovered FreeRDP incorrectly handled bitmaps.  A
malicious server
could use this issue to cause FreeRDP to crash, resulting in a denial
of
service, or possibly execute arbitrary code. (CVE-2018-8786, CVE-2018-
8787)

Eyal Itkin discovered FreeRDP incorrectly handled certain stream
encodings.  A
malicious server could use this issue to cause FreeRDP to crash,
resulting in a
denial of service, or possibly execute arbitrary code. This issue only
applies
to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-
8788)

Eyal Itkin discovered FreeRDP incorrectly handled NTLM
authentication.  A
malicious server could use this issue to cause FreeRDP to crash,
resulting in a
denial of service, or possibly execute arbitrary code. This issue only
applies
to Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 18.10. (CVE-2018-
8789)" );
	script_tag( name: "affected", value: "'freerdp' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS." );
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
report = "";
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-client1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "libfreerdp-client1.1", ver: "1.1.0~git20140921.1.440916e+dfsg1-", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

