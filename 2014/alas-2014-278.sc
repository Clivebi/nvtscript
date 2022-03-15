if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120562" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:29:39 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-278)" );
	script_tag( name: "insight", value: "GnuPG 1.x before 1.4.16 generates RSA keys using sequences of introductions with certain patterns that introduce a side channel, which allows physically proximate attackers to extract RSA keys via a chosen-ciphertext attack and acoustic cryptanalysis during decryption. NOTE: applications are not typically expected to protect themselves from acoustic side-channel attacks, since this is arguably the responsibility of the physical device. Accordingly, issues of this type would not normally receive a CVE identifier. However, for this issue, the developer has specified a security policy in which GnuPG should offer side-channel resistance, and developer-specified security-policy violations are within the scope of CVE." );
	script_tag( name: "solution", value: "Run yum update gnupg to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-278.html" );
	script_cve_id( "CVE-2013-4576" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
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
	if(!isnull( res = isrpmvuln( pkg: "gnupg", rpm: "gnupg~1.4.16~2.23.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnupg-debuginfo", rpm: "gnupg-debuginfo~1.4.16~2.23.amzn1", rls: "AMAZON" ) )){
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

