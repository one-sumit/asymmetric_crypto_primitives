import 'package:flutter/material.dart';
import 'package:asymmetric_crypto_primitives/asymmetric_crypto_primitives.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({Key? key}) : super(key: key);

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  TextEditingController writeKeyController = TextEditingController();
  TextEditingController writeDataController = TextEditingController();
  TextEditingController readKeyController = TextEditingController();
  TextEditingController deleteKeyController = TextEditingController();
  TextEditingController editKeyController = TextEditingController();
  TextEditingController editDataController = TextEditingController();

  String writeResult = "";
  String readResult = '';
  String deleteResult = '';
  String editResult = '';

  @override
  void initState() {
    super.initState();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('storage example app'),
        ),
        body: SingleChildScrollView(
          child: Center(
              child: Column(
            children: [
              const Divider(
                thickness: 5,
              ),
              const Text(
                '1. Write',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
              ),
              TextFormField(
                controller: writeKeyController,
                decoration: const InputDecoration(hintText: "key"),
              ),
              TextFormField(
                controller: writeDataController,
                decoration: const InputDecoration(hintText: "data"),
              ),
              RawMaterialButton(
                onPressed: () async {
                  if (writeDataController.text.isNotEmpty &&
                      writeKeyController.text.isNotEmpty) {
                    var result = await AsymmetricCryptoPrimitives.writeData(
                        writeKeyController.text, writeDataController.text);
                    if (result == true) {
                      setState(() {
                        writeResult = 'Success!';
                      });
                    } else {
                      setState(() {
                        writeResult = 'Failure!';
                      });
                    }
                  }
                },
                child: const Text('Write!'),
              ),
              Text(writeResult),
              const Divider(),
              const Text(
                '2. Read',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
              ),
              TextFormField(
                controller: readKeyController,
                decoration: const InputDecoration(hintText: "key"),
              ),
              RawMaterialButton(
                onPressed: () async {
                  if (readKeyController.text.isNotEmpty) {
                    var result = await AsymmetricCryptoPrimitives.readData(
                        readKeyController.text);
                    if (result != false) {
                      setState(() {
                        readResult = result;
                      });
                    } else {
                      setState(() {
                        readResult = 'Failure!';
                      });
                    }
                  }
                },
                child: const Text('Read!'),
              ),
              Text(readResult),
              const Divider(),
              const Text(
                '3. Delete',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
              ),
              TextFormField(
                controller: deleteKeyController,
                decoration: const InputDecoration(hintText: "key"),
              ),
              RawMaterialButton(
                onPressed: () async {
                  if (deleteKeyController.text.isNotEmpty) {
                    var result = await AsymmetricCryptoPrimitives.deleteData(
                        deleteKeyController.text);
                    if (result == true) {
                      setState(() {
                        deleteResult = "Deleted!";
                      });
                    } else {
                      setState(() {
                        deleteResult = "Failure!";
                      });
                    }
                  }
                },
                child: const Text('Delete!'),
              ),
              Text(deleteResult),
              const Divider(),
              const Text(
                '4. Edit',
                style: TextStyle(fontWeight: FontWeight.bold, fontSize: 25),
              ),
              TextFormField(
                controller: editKeyController,
                decoration: const InputDecoration(hintText: "key"),
              ),
              TextFormField(
                controller: editDataController,
                decoration: const InputDecoration(hintText: "data"),
              ),
              RawMaterialButton(
                onPressed: () async {
                  if (editDataController.text.isNotEmpty &&
                      editKeyController.text.isNotEmpty) {
                    var result = await AsymmetricCryptoPrimitives.editData(
                        editKeyController.text, editDataController.text);
                    if (result == true) {
                      setState(() {
                        editResult = 'Success!';
                      });
                    } else {
                      setState(() {
                        editResult = 'Failure!';
                      });
                    }
                  }
                },
                child: const Text('Edit!'),
              ),
              Text(editResult),
              const Divider(),
            ],
          )),
        ),
      ),
    );
  }
}
