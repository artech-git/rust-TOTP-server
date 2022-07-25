
<div >
<img src="./assest/key-chain.png" width="100" height=100/> <h1>TOTP-server</h1>
</div>

This project implements a basic Time Based Authentication system implemented in Rust which can be deployed on aws-lambda or can be operated on native system as well

to start the server
`~$ cargo run ` 

to test the code 
`~$ cargo test` 

---


## For sending a fresh request   


`~$ curl -X GET http://localhost:3000/register -v `

response produced contains a QR code which you can scan in your 2FA app to verify

<img src="./assest/register.png" style ="border:orange; border-width:1px; border-style:solid;"/>

&nbsp;
&nbsp;


<p style="float: left;">
  <img src="./assest/b.gif" width="200" height="400" style="border:orange; border-width:2px; border-style:solid;"/> 
  &nbsp;
  &nbsp;
  &nbsp;
  &nbsp;
  &nbsp;
  &nbsp;
  &nbsp;
  <ol align = "center">
    <h2>
      <br>
      <br>
      <br>
      <li>open the 2FA app (google authenticator)</li>
      <li>scan the QR generated in the response</li>
      <li>Accept the account generated</li>
      <li>now you can enter the code in 30 second interval</li>
    </h2>
  </ol>
</p>

