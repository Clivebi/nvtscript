if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882928" );
	script_version( "2021-05-25T06:00:12+0200" );
	script_tag( name: "last_modification", value: "2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2018-07-27 05:59:47 +0200 (Fri, 27 Jul 2018)" );
	script_cve_id( "CVE-2018-5188", "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12372", "CVE-2018-12373", "CVE-2018-12374" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 18:44:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for thunderbird CESA-2018:2251 centos6" );
	script_tag( name: "summary", value: "Check the version of thunderbird" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and
newsgroup client.

This update upgrades Thunderbird to version 52.9.1.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 61, Firefox ESR 60.1, and
Firefox ESR 52.9 (CVE-2018-5188)

  * Mozilla: Buffer overflow using computed size of canvas element
(CVE-2018-12359)

  * Mozilla: Use-after-free using focus() (CVE-2018-12360)

  * Mozilla: Integer overflow in SSSE3 scaler (CVE-2018-12362)

  * Mozilla: Use-after-free when appending DOM nodes (CVE-2018-12363)

  * Mozilla: CSRF attacks through 307 redirects and NPAPI plugins
(CVE-2018-12364)

  * thunderbird: S/MIME and PGP decryption oracles can be built with HTML
emails (CVE-2018-12372)

  * thunderbird: S/MIME plaintext can be leaked through HTML reply/forward
(CVE-2018-12373)

  * Mozilla: Compromised IPC child process can list local filenames
(CVE-2018-12365)

  * Mozilla: Invalid data handling during QCMS transformations
(CVE-2018-12366)

  * thunderbird: Using form to exfiltrate encrypted mail part by pressing
enter in form field (CVE-2018-12374)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Alex Gaynor, Christoph Diehl, Christian Holler, Jason
Kratzer, David Major, Jon Coppeard, Nicolas B. Pierron, Marcia Knous,
Ronald Crane, Nils, F. Alonso (revskills), David Black, and OSS-Fuzz as the
original reporters." );
	script_tag( name: "affected", value: "thunderbird on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:2251" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-July/022975.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~52.9.1~1.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

