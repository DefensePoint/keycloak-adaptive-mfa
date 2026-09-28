<#import "template.ftl" as layout>

<@layout.registrationLayout displayInfo=false; section>
    <#if section == "form">
        <form id="screenResForm" action="${url.loginAction}" method="post">
            <input id="screenRes" type="hidden" name="screenRes"/>
            <p style="text-align: left;">Please wait...</p>
        </form>
    </#if>
</@layout.registrationLayout>
