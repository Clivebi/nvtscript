if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.851299" );
	script_version( "2021-09-20T11:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-20 11:01:47 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-05-06 05:19:37 +0200 (Fri, 06 May 2016)" );
	script_cve_id( "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "openSUSE: Security Advisory for openssl (openSUSE-SU-2016:1240-1)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl fixes the following issues:

  - CVE-2016-2105: EVP_EncodeUpdate overflow (bsc#977614)

  - CVE-2016-2106: EVP_EncryptUpdate overflow (bsc#977615)

  - CVE-2016-2107: Padding oracle in AES-NI CBC MAC check (bsc#977616)

  - CVE-2016-2108: Memory corruption in the ASN.1 encoder (bsc#977617)

  - CVE-2016-2109: ASN.1 BIO excessive memory allocation (bsc#976942)

  - bsc#976943: Buffer overrun in ASN1_parse" );
	script_tag( name: "affected", value: "openssl on openSUSE 13.1" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "openSUSE-SU", value: "2016:1240-1" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSE13\\.1" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "openSUSE13.1"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-devel", rpm: "libopenssl-devel~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debugsource", rpm: "openssl-debugsource~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-devel-32bit", rpm: "libopenssl-devel-32bit~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-32bit", rpm: "libopenssl1_0_0-32bit~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo-32bit", rpm: "libopenssl1_0_0-debuginfo-32bit~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~1.0.1k~11.87.1", rls: "openSUSE13.1" ) )){
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

