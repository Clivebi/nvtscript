if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120723" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2016-10-26 15:38:20 +0300 (Wed, 26 Oct 2016)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-734)" );
	script_tag( name: "insight", value: "Multiple flaws have been discovered in libtiff. A remote attacker could exploit these flaws to cause a crash or memory corruption and, possibly, execute arbitrary code by tricking an application linked against libtiff into processing specially crafted files. (CVE-2014-9655, CVE-2015-1547, CVE-2015-8784, CVE-2015-8683, CVE-2015-8665, CVE-2015-8781, CVE-2015-8782, CVE-2015-8783, CVE-2016-3990, CVE-2016-5320 )" );
	script_tag( name: "solution", value: "Run yum update compat-libtiff3 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-734.html" );
	script_cve_id( "CVE-2014-9655", "CVE-2016-5320", "CVE-2016-3990", "CVE-2015-8784", "CVE-2015-8665", "CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2015-1547", "CVE-2015-8683" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Amazon Linux Local Security Checks" );
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
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "compat-libtiff3", rpm: "compat-libtiff3~3.9.4~18.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "compat-libtiff3-debuginfo", rpm: "compat-libtiff3-debuginfo~3.9.4~18.14.amzn1", rls: "AMAZON" ) )){
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

