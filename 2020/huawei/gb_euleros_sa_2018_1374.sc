if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.2.2018.1374" );
	script_cve_id( "CVE-2014-4975", "CVE-2014-8080", "CVE-2014-8090" );
	script_tag( name: "creation_date", value: "2020-01-23 11:23:43 +0000 (Thu, 23 Jan 2020)" );
	script_version( "2021-07-22T02:24:02+0000" );
	script_tag( name: "last_modification", value: "2021-07-22 02:24:02 +0000 (Thu, 22 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-29 01:35:00 +0000 (Tue, 29 Aug 2017)" );
	script_name( "Huawei EulerOS: Security Advisory for ruby (EulerOS-SA-2018-1374)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Huawei EulerOS Local Security Checks" );
	script_dependencies( "gb_huawei_euleros_consolidation.sc" );
	script_mandatory_keys( "ssh/login/euleros", "ssh/login/rpms",  "ssh/login/release=EULEROSVIRT\\-2\\.5\\.1" );
	script_xref( name: "Advisory-ID", value: "EulerOS-SA-2018-1374" );
	script_xref( name: "URL", value: "https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1374" );
	script_tag( name: "summary", value: "The remote host is missing an update for the Huawei EulerOS 'ruby' package(s) announced via the EulerOS-SA-2018-1374 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The REXML parser in Ruby 1.9.x before 1.9.3-p550, 2.0.x before 2.0.0-p594, and 2.1.x before 2.1.4 allows remote attackers to cause a denial of service (memory consumption) via a crafted XML document, aka an XML Entity Expansion (XEE) attack.(CVE-2014-8080)

The REXML parser in Ruby 1.9.x before 1.9.3 patchlevel 551, 2.0.x before 2.0.0 patchlevel 598, and 2.1.x before 2.1.5 allows remote attackers to cause a denial of service (CPU and memory consumption) a crafted XML document containing an empty string in an entity that is used in a large number of nested entity references, aka an XML Entity Expansion (XEE) attack. NOTE: this vulnerability exists because of an incomplete fix for CVE-2013-1821 and CVE-2014-8080.(CVE-2014-8090)

Off-by-one error in the encodes function in pack.c in Ruby 1.9.3 and earlier, and 2.x through 2.1.2, when using certain format string specifiers, allows context-dependent attackers to cause a denial of service (segmentation fault) via vectors that trigger a stack-based buffer overflow.(CVE-2014-4975)" );
	script_tag( name: "affected", value: "'ruby' package(s) on Huawei EulerOS Virtualization 2.5.1." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "EULEROSVIRT-2.5.1"){
	if(!isnull( res = isrpmvuln( pkg: "ruby", rpm: "ruby~2.0.0.353~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-irb", rpm: "ruby-irb~2.0.0.353~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ruby-libs", rpm: "ruby-libs~2.0.0.353~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-bigdecimal", rpm: "rubygem-bigdecimal~1.2.0~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-io-console", rpm: "rubygem-io-console~0.4.2~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-json", rpm: "rubygem-json~1.7.7~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-psych", rpm: "rubygem-psych~2.0.0~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygem-rdoc", rpm: "rubygem-rdoc~4.0.0~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "rubygems", rpm: "rubygems~2.0.14~23.h9", rls: "EULEROSVIRT-2.5.1" ) )){
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

